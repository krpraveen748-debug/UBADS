# UBADS Windows Endpoint Agent (Phase 11-14)

**Status:** Implemented and verified locally against the real backend and
real Windows Event Log (real 4624 authentication events, plus
process/file activity, have since been collected — see root README's
Phase 12 sections). Runs as a foreground Python process from source, can
be packaged into a standalone local Windows `.exe` with PyInstaller (Phase
13), and that `.exe` can be wrapped in a real local
`UBADS-Agent-Setup.exe` installer with Inno Setup (Phase 14) — see
"Building the local installer" below. **Not** packaged as a Windows
*service* or installed automatically by anything in
this project; the packaged executable is still a manually-run foreground
process, and it is a local/dev/test build, not a signed release artifact.

## What this is

A real Windows endpoint agent that collects genuine Windows Security
events (reusing `log-collector/`'s collector exactly), remembers what it
has already collected with a persistent per-category cursor, and submits
new events to the UBADS backend over HTTP, authenticated with this
endpoint's own per-agent credential.

```
Authorized Windows Endpoint
        │
        ▼
Windows Event Collector      (log-collector/collector.py, reused as-is;
        │                     cursor-aware via after_record_id=)
        │  normalize (event_parser.normalize_event, inside collect_events)
        ▼
Local validation             (validation.validate_event, reused as-is)
        │
        ▼
Endpoint identity            (agent/identity.py — stable local UUID4)
        │
        ▼
Per-agent credential         (agent/credential_store.py — this endpoint's
        │                     own secret, obtained once via enrollment)
        ▼
Backend client                (agent/backend_client.py — X-Endpoint-Id +
        │                      X-Agent-Credential)
        ▼
POST /api/ingest/events       (backend validates + stores again, attributes
        │                      to the authenticated endpoint — see
        │                      backend/README.md)
        ▼
data/app.db (SQLite, same file log-collector/backend already share)
        │
        ▼  (only on confirmed success)
Collection checkpoint         (agent/checkpoint.py — per-category cursor)
```

## Why this reuses, rather than duplicates, log-collector

`agent/pipeline_bridge.py` adds `log-collector/` to `sys.path` and imports
its `collector`, `event_parser`, and `validation` modules directly — the
same sys.path-bridging pattern `ml-service/feature_engineering.py` and
`backend/app/repositories/pipeline_bridge.py` already use. Windows Event
Log querying (`collector.collect_events()`, `CATEGORY_EVENT_IDS`),
normalization (`event_parser.normalize_event()`, called internally by
`collect_events()`), and validation (`validation.validate_event()`) are
never re-implemented here — only reused. Phase 11 adds two small,
additive primitives to `collector.py` itself (`after_record_id=` cursor
filtering and `raise_errors=True` typed exceptions) rather than a second
collector.

## Files

| File | Purpose |
|---|---|
| `agent.py` | CLI entry point — `--identity`, `--status`, `--collect`, `--run`. |
| `config.py` | `AgentSettings` — development `.env` sources and protected installed JSON configuration. |
| `identity.py` | Stable local endpoint identity, persisted to the selected agent state directory. |
| `credential_store.py` | This endpoint's own per-agent credential, persisted to the selected agent state directory. |
| `checkpoint.py` | Persistent per-category collection cursor in the selected agent state directory. |
| `runtime_state.py` | Last successful collection/upload timestamps in the selected agent state directory. |
| `backend_client.py` | The one place this agent makes HTTP requests — enroll/register/heartbeat/ingest/health/ready, with bounded retry. |
| `state.py` | Bounded local buffer (`pending_events.jsonl`, capped at 500) for events that couldn't be sent yet. |
| `pipeline_bridge.py` | sys.path bridge into `log-collector/` (see above); frozen-aware since Phase 13. |
| `paths.py` | Resolves source/test paths and the protected ProgramData layout for an installed production agent. |
| `protected_storage.py` | Creates and verifies the installed agent's restrictive Windows storage ACLs. |
| `ubads_agent.spec` | **Phase 13.** PyInstaller build recipe — tracked in git (it's a build *recipe*, not build *output*). |
| `requirements-build.txt` | **Phase 13.** Build-only dependency (`pyinstaller`) — not needed to run the agent from source. |
| `installer/ubads_agent.iss` | **Phase 14.** Inno Setup installer script — tracked in git, produces `UBADS-Agent-Setup.exe`. |
| `installer/env.example` | Development configuration example; it is not copied into production installations. |
| `installer/after-install.txt` | **Phase 14.** Explicit next-steps text shown on the installer's finish page. |

## Endpoint identity

`endpoint_id` is a randomly generated UUID4, generated once and persisted
locally — **never** derived from username, IP address, or MAC
address/hardware serial. Verified: the same ID is returned across repeated
runs.

`display_name` / `operating_system` come from `platform.node()` /
`platform.platform()` — the same computer-name concept every event in this
project already records (`computer_name`), not a new hardware identifier.

```powershell
python agent.py --identity
```

## Per-agent credential (Phase 11)

Each endpoint has its **own** credential — not the single shared key every
endpoint used in Phase 9/10:

```
Endpoint A → credential A
Endpoint B → credential B
```

Legacy shared-key enrollment is available only in development. Installed
production agents use the one-time authorization from an approved portal
request:

1. The user downloads the endpoint-specific installer from the approved
   request in the portal.
2. The installer hands its one-time authorization to the agent without
   placing the code in a command argument, environment variable, or file.
3. The agent saves the endpoint credential under the protected state
   directory using Windows CurrentUser DPAPI.

Every later call — re-registration, heartbeat, ingestion — authenticates
with `X-Endpoint-Id` + `X-Agent-Credential` instead. If the stored
credential is ever lost or an operator revokes it
(`backend/manage_endpoints.py --revoke-credential <id>`), the agent
re-enrolls the same way on its next run (using the enrollment key again).

`AGENT_API_KEY` belongs only to legacy development enrollment. A deployed
endpoint must be enrolled through its approved portal request and
endpoint-specific installer; do not copy the backend's shared key to an
endpoint or place it in an installed agent configuration.

## Configuration

Source/development runs read `config/.env`, `agent.env`, and process
environment settings. Pytest omits dotenv files and uses isolated test
data. The frozen production agent does not read executable-adjacent
`.env`, user-writable `agent.env`, or process environment overrides.

| Setting | Meaning | Development default |
|---|---|---|
| `BACKEND_URL` | Base URL of the UBADS backend | `http://127.0.0.1:8000` |
| `AGENT_API_KEY` | Legacy shared enrollment key (development/test only) | unset |
| `ENDPOINT_ID` | Development/test-only explicit identity override | unset (auto-generated) |
| `COLLECTION_INTERVAL` | Seconds between cycles in `--run` | `60` |
| `BATCH_SIZE` | Max events collected per category per cycle | `50` |
| `REQUEST_TIMEOUT` | Seconds per HTTP request | `10.0` |
| `LOG_LEVEL` | Agent logging level | `INFO` |
| `CATEGORIES` | Comma-separated `log-collector` categories to collect | all four |
| `LOG_CHANNEL` | Windows Event Log channel | `Security` |

No API key or credential is hard-coded. Installed production configuration
is a protected JSON file at
`%ProgramData%\UBADS\Agent\config\agent.json`, written by successful
one-time enrollment. It has `version: 1`, a required `backend_url`, and
optional collection settings (`categories`, `log_channel`,
`collection_interval`, `batch_size`, `request_timeout`, `log_level`).
Production requires a remote HTTPS backend; loopback and HTTP URLs are
rejected. `ENDPOINT_ID`, `AGENT_API_KEY`, path overrides, and task-name
overrides are not accepted from production process environment.

The installed agent uses `%ProgramData%\UBADS\Agent\state` for credentials,
identity, checkpoints, runtime state, and pending events, and
`%ProgramData%\UBADS\Agent\logs` for logs. SYSTEM and Administrators own
the protected ACL boundary; standard users are not granted write access.
The agent verifies protected ACLs and ownership before reading an existing
production config and fails closed on an insecure or inaccessible store.
Credentials remain DPAPI CurrentUser-protected to preserve the existing
interactive scheduled-task identity model; no LocalMachine credential
migration or service conversion is performed here.

If installed state is missing/corrupt, the agent does not replace an
existing endpoint identity. A prior LocalAppData state tree is left
untouched; the installer blocks upgrading when it detects legacy state
until a separately reviewed migration is available.

## CLI

```powershell
cd agent
pip install -r requirements.txt

python agent.py --identity   # show local endpoint identity (safe fields only)
python agent.py --status     # check config, credential, checkpoints, backend connectivity
python agent.py --collect    # one real collection-and-submit cycle
python agent.py --run        # run continuously (Ctrl+C to stop) — no Windows service yet
```

## Collection cursor / checkpoint (Phase 11)

Prior phases re-read the same recent window of the event log every cycle.
The agent now remembers, **per category**, the highest Windows
`EventRecordID` it has already collected and confirmed delivered
(`agent/checkpoint.py`), so later cycles only ask Windows for events newer
than that — a real, strictly-increasing per-channel-per-computer sequence
number, not the Event ID (4624 etc.), which is neither unique nor ordered.

**Delivery ordering** — the checkpoint only ever moves forward *after* a
confirmed successful backend response for the exact batch containing those
events:

```
collect (candidate cursor per category)
    → validate
    → send (previously-buffered events + newly collected ones)
    → confirm (backend accepted the batch)
    → advance checkpoint (only now, only for categories in this batch)
```

If the send fails, the checkpoint is left untouched and the events stay in
the bounded local buffer — the next cycle naturally retries the same
range instead of skipping anything. Events that are already buffered are
never re-added just because they were re-collected again while waiting.

**Restart persistence**: the checkpoint is written to
`agent/.state/checkpoint.json` and read fresh on every invocation (this is
a short-lived CLI process, not a resident one).

**Corruption / rollover recovery**: a corrupt or unreadable checkpoint
file is treated as "no checkpoint yet" — never a crash. If the Windows log
was cleared (its current newest `EventRecordID` is lower than a saved
cursor), that is detected and the affected category's cursor is reset
rather than requesting an impossible range.

## Reliable delivery (kept simple, on purpose)

- HTTP failures (connection error, timeout, 5xx) retry with bounded
  exponential backoff (3 attempts max) — never an infinite tight loop.
- 401 (bad/missing credential) and the auth-not-configured 503 are **not**
  retried — retrying a credential problem would never succeed.
- If a batch still can't be sent after retries, it's appended to a
  bounded local buffer (`agent/.state/pending_events.jsonl`, capped at
  500 events — oldest dropped first) and retried on the next cycle,
  instead of being lost or crashing the agent, and the collection
  checkpoint is **not** advanced for that batch.
- Duplicate submission is avoided the same way log-collector's own local
  pipeline already avoids it: the backend's `storage.insert_event()`
  dedup-by-`event_uid` logic (Phase 3, namespaced per endpoint since Phase
  11) is reused unchanged — re-sending the same real event is safe; it's
  reported back as a `duplicate`, not inserted twice.

## Security

Uses the Phase 11 per-agent credential model — `X-Endpoint-Id` +
`X-Agent-Credential` on every register/heartbeat/ingest call after
enrollment (see backend/README.md and
`backend/app/security/agent_auth.py`). Neither the enrollment key nor the
per-agent credential is ever logged, printed, or included in any error
message this agent produces.

## Privacy — what this agent collects

Identical to `log-collector`'s existing scope (Phase 2-4), because it
reuses that exact collection code:

**Collects:** authentication events (logon/logoff), file activity
(create/access/delete metadata under an explicitly audited folder),
process activity (process name/PID/parent), device activity (USB
connect/recognition) — all as normalized metadata (timestamps, account
names, computer names, event types).

**Never collects:** passwords, password hashes, browser
credentials/cookies, private messages, email contents, document contents,
keystrokes, screenshots, webcam data, or microphone data. This agent adds
no new monitoring capability beyond what `log-collector/` already
implements — it only transports the same data over HTTP instead of
writing it to a local file directly.

## Real Windows verification (Phase 11)

Run from an ordinary (non-Administrator) PowerShell, against a real local
backend, with a real `AGENT_API_KEY` configured:

```powershell
python agent.py --status     # shows agent_credential_enrolled: false, checkpoints: null
python agent.py --collect
```

**Verified for real, this phase:**
- Enrollment against the real backend: a new random per-agent credential
  was issued and persisted to `agent/.state/credentials.json`; re-running
  `--collect` did **not** re-enroll (the stored credential was reused).
- Real Windows Security-log collection returned honestly
  `SECURITY_LOG_ACCESS_DENIED` (not a crash, not a silent empty list) when
  run without Administrator privileges.
- Real Windows Application-log collection (event ID 1001, already
  collected in Phase 10) end-to-end through the full Phase 11 pipeline:
  enrollment → authenticated ingestion → endpoint attribution in
  `data/app.db` → checkpoint advance only after a confirmed `200` — a
  second immediate `--collect` cycle then requested `after_record_id=<the
  advanced cursor>` and correctly fetched nothing new.
- A simulated backend-unreachable failure buffered the collected events
  locally and left the checkpoint untouched, confirmed by re-reading it
  after the failed attempt.

**NOT YET VERIFIED (requires Administrator — see root README):**
real Security-log collection of authentication/file/process/device
events with a human account attributed to them; multi-day collection.

## Real Windows verification (Phase 12A — re-verified, still blocked)

No code changed this phase; this was a verification-only pass, still
without Administrator rights in this session:

- `--collect` was run 3 times as 3 separate process invocations (first,
  second, a simulated "restart"+third) against the real Security channel
  with the default categories. All 3 reported `SECURITY_LOG_ACCESS_DENIED`
  for all four categories, honestly, with `collected: 0` every time.
- `agent/.state/checkpoint.json` was inspected directly after all 3 runs:
  no `Security::*` entry exists — confirms an access-denied category never
  produces a candidate cursor, so nothing is (or could be) falsely
  advanced.
- A read-only `auditpol /get /subcategory:"Logon"` probe (outside the
  agent, to distinguish "the collector has a bug" from "this genuinely
  needs Administrator") also failed with `0x522 — A required privilege is
  not held by the client` — confirming the requirement is a real Windows
  privilege check, not a collector-side limitation.
- The agent's stored per-agent credential (issued in Phase 11) was reused
  without re-enrolling, confirming credential persistence survives across
  phases/sessions, not just within one.

**Still NOT VERIFIED (requires Administrator):** real Security-log content
collection of any category; human-account attribution from real
Security-log events (there are currently zero such events to classify).

## Building a local Windows executable (Phase 13)

> **Historical packaging notes below:** the LocalAppData and executable-
> adjacent `.env` behavior described in the original Phase 13 verification
> was replaced by Stage 4H-2. Current installed-agent behavior is documented
> in the Configuration section above; these notes are not deployment
> instructions for a production install.

**Status: IMPLEMENTED and LOCALLY VERIFIED.** Not signed, not published,
not deployed anywhere — a local/dev/test artifact only. There is no
Azure/cloud release hosting yet (PLANNED, not implemented — see root
README).

### Packaging approach: PyInstaller

The agent is pure Python plus `pywin32`, `requests`, `pydantic-settings`,
and `sqlalchemy`/`python-dotenv` (transitively, via `log-collector`) —
exactly the kind of dependency set PyInstaller packages well, and it is
already the de facto standard for turning a Python CLI into a single
Windows `.exe` without requiring end users to install Python. No other
approach (a full MSI installer, `cx_Freeze`, Nuitka, etc.) was justified
for a **local** artifact at this stage.

### What packaging required changing (and why)

Freezing a script with PyInstaller changes what `__file__` and the
current working directory mean at runtime — a frozen module's `__file__`
resolves inside PyInstaller's *temporary* extraction directory
(`sys._MEIPASS`), which is deleted after the process exits. Every prior
phase's state modules (`identity.py`, `state.py`, `checkpoint.py`,
`credential_store.py`, `runtime_state.py`) computed
`STATE_DIR = Path(__file__).resolve().parent / ".state"` directly — under
a frozen build that would silently recreate a brand-new, empty state
directory on *every single run*, destroying the stable endpoint identity,
the per-agent credential, the collection checkpoint, and the pending-event
buffer between runs. That would have been a real regression, not a
packaging detail.

**Fix:** a new `agent/paths.py` is now the ONE place that decides where
state and config live:

- **Running from source** (`python agent.py ...`, and every existing
  test): byte-for-byte unchanged — `agent/.state/` and `config/.env`,
  exactly as every prior phase.
- **Running as a packaged `.exe`**: state persists to
  `%LOCALAPPDATA%\UBADS\Agent\.state\` (a stable, per-user, OS-standard
  location — never deleted between runs), and configuration is read from
  a `.env` file placed **next to the .exe itself** (via `sys.executable`),
  never baked into the binary.

Nothing about collection, validation, delivery ordering, retry behavior,
authentication, or privacy scope changed — only *where on disk* the
existing state/config files live. This was verified for real (see below),
not just reasoned about.

### Build it yourself

```powershell
cd agent
pip install -r requirements.txt              # the agent's own runtime deps
pip install -r requirements-build.txt        # + pyinstaller (build-only)

pyinstaller --clean --noconfirm ubads_agent.spec
```

**Artifact produced at:** `agent/dist/ubads-agent.exe` (a single ~18 MB
file; `agent/build/` holds PyInstaller's intermediate working files — both
directories are gitignored, never committed, and safe to delete and
rebuild at any time).

### Configuring the packaged executable

No credential, backend URL, or endpoint ID is ever embedded in the
executable. Place a plain-text `.env` file **next to `ubads-agent.exe`**
(same folder), e.g.:

```
BACKEND_URL=http://your-backend-host:8000
AGENT_API_KEY=the-shared-enrollment-key
COLLECTION_INTERVAL=60
BATCH_SIZE=50
CATEGORIES=authentication,file_activity,process_activity,device_activity
LOG_LEVEL=INFO
```

Every field is the same `AgentSettings` field documented in
"Configuration" above — nothing new. Real OS environment variables (e.g.
set via `setx` or a scheduled task's environment) take priority over this
file if both are present, giving a second configuration mechanism for
non-interactive deployment later.

### Running it

```powershell
cd agent\dist
.\ubads-agent.exe --identity     # safe, local-only, no network call
.\ubads-agent.exe --status       # config + backend connectivity check
.\ubads-agent.exe --collect      # one real collection-and-submit cycle
.\ubads-agent.exe --run          # continuous, Ctrl+C to stop
```

Reading the Security log still requires Administrator (or "Event Log
Readers" membership) exactly as running from source does — packaging
changes nothing about that requirement. This executable does **not**
install itself as a service, does **not** persist itself at startup, and
does **not** enable any Windows audit policy on its own; those remain
explicit, manual, Administrator-run steps documented in
`log-collector/README.md`.

### Removing it (source/development executable only)

There is no installer to "uninstall" — delete `ubads-agent.exe` and, if
you also want to remove its persisted state/credential,
`%LOCALAPPDATA%\UBADS\Agent\` (this deletes the endpoint's local identity
and stored credential; re-running the exe afterward re-enrolls as if new).
No registry entries, services, or scheduled tasks are created by this
source/development executable. Do not use this guidance for an installed
production endpoint.

### Verification performed (real, this phase)

- `pyinstaller --clean --noconfirm ubads_agent.spec` completed
  successfully on the first attempt; `agent/dist/ubads-agent.exe` exists
  (confirmed via `Get-Item`, ~17.6 MB, a real Windows PE32+ executable).
- `--identity`, run with `LOCALAPPDATA` pointed at an isolated temporary
  directory (so this never touched the real dev machine's state): created
  `UBADS\Agent\.state\identity.json` under that isolated directory, and a
  **second** invocation returned the **same** `endpoint_id` — proving
  persistence survives across separate process launches of the packaged
  executable, not just in-memory.
- `-h` printed argparse's usage correctly (`ubads-agent.exe` as the
  program name).
- `--status`, with a `.env` file placed next to the built `.exe`
  (`CATEGORIES=authentication,file_activity`, a non-default value):
  reported those exact categories back, `pywin32_available: true`
  (confirming pywin32/`win32evtlog` bundled and imports correctly in the
  frozen build), and `backend_health: reachable` / `backend_ready: ready`
  against the real local backend — all without collecting or transmitting
  any event data.
- Full Python test suite and frontend build both still pass (see below).

**Update (Phase 14):** `--collect` from the packaged executable was since
run for real, twice, against the real backend — see "Building the local
installer" below. It correctly enrolled, obtained a unique credential, and
honestly reported `SECURITY_LOG_ACCESS_DENIED` (no Administrator in that
session) — the earlier gap is closed.

**Still NOT YET VERIFIED:** `--collect`/`--run` actually retrieving real
Security-log content from a *packaged* executable specifically under
Administrator (verified from source in earlier phases; not yet repeated
with the `.exe`); running the executable on a machine other than the one
it was built on; any antivirus/security-software reaction to the built
`.exe` (PyInstaller executables are occasionally flagged by some antivirus
heuristics — if that happens, see root README's guidance on 360 Total
Security: document it and stop, never disable protection or add
exclusions to work around it).

## Building the local installer (Phase 14 — `UBADS-Agent-Setup.exe`)

**Status: IMPLEMENTED, LOCALLY VERIFIED.** LOCAL VERIFIED means: built on
this development machine, and its full install→configure→enroll→collect
flow was exercised for real against a real local backend. It does **not**
mean PRODUCTION READY — see the explicit distinction at the end of this
section.

### Why an installer, on top of the Phase 13 `.exe`

Phase 13 produced `ubads-agent.exe` — a real, working executable, but
still something you'd hand someone as a bare file with instructions.
"Genuinely distributable to other authorized Windows users" means a
normal double-click installer/uninstaller with a proper install location,
Start Menu entries, and no need to know PyInstaller exists.

### Packaging approach: Inno Setup

Inno Setup was chosen because it is free, widely used for exactly this
(a single `.exe` installer for a Windows console/GUI app), produces one
self-contained `Setup.exe`, and needs no code changes to the agent at
all — it only packages the ALREADY-BUILT `agent/dist/ubads-agent.exe`
(Phase 13) plus a configuration template. Installed via `winget install
--id JRSoftware.InnoSetup` for this build; any Inno Setup 6.x install
works.

### Build it yourself

```powershell
# 1. Build the agent executable first (Phase 13 — skip if already built)
cd agent
pip install -r requirements.txt
pip install -r requirements-build.txt
pyinstaller --clean --noconfirm ubads_agent.spec

# 2. Compile the installer around it
& "C:\Users\<you>\AppData\Local\Programs\Inno Setup 6\ISCC.exe" installer\ubads_agent.iss
```

**Artifact produced at:** `agent/dist/UBADS-Agent-Setup.exe` (~20 MB,
gitignored, rebuildable at any time — never committed). It sits right next
to `ubads-agent.exe` from step 1.

### What the installer does — and deliberately does NOT do

It copies `ubads-agent.exe` and a `.env.example` configuration template
into `C:\Program Files\UBADS Agent\` (installing there requires
Administrator — normal Windows installer behavior, unrelated to anything
below), creates a Start Menu group, and registers a normal uninstaller.

It does **NOT**:
- enable any Windows audit policy (`auditpol` is never invoked by setup)
- enroll any endpoint or contact any backend during installation
- start the agent, install a Windows service, or create a scheduled task
- write a real `AGENT_API_KEY`/`BACKEND_URL` anywhere — only the example
  template, with every value blank or a safe local default
- touch antivirus/security software
- **launch anything at all after installation** (Phase 15A — see below;
  there is no `[Run]` section in `ubads_agent.iss`, not even an optional,
  unchecked one)

The installer's finish page shows explicit next steps (configure, then
have an Administrator review and run the relevant `log-collector/scripts/
enable_*_audit.ps1` script if activity categories are wanted, then enroll)
— see `agent/installer/after-install.txt` for the exact text shown.

### Fixed: a console window briefly flashing during/after install (Phase 15A)

**Status: IMPLEMENTED, LOCALLY VERIFIED.**

**Root cause:** `ubads_agent.iss` previously had a `[Run]` section offering
an optional, default-*unchecked* finish-page checkbox — "Show this
endpoint's local identity now" — that, if checked, ran `ubads-agent.exe
--identity`. `ubads-agent.exe` is deliberately a **console-subsystem**
executable (`ubads_agent.spec`'s `console=True`, needed so
`--identity`/`--status`/`--collect`/`--run` print normally when a user
runs them from a terminal on purpose — see "Preserved" below). Launching
*any* console-subsystem process — even one that does no network I/O and
exits almost instantly, like `--identity` — opens a real console window
for that instant, which is exactly the "briefly opens and then closes"
symptom. This was **not** the Inno Setup installer UI itself (a normal
GUI wizard throughout, unaffected) and **not** a PyInstaller packaging
defect — it was one specific, optional, installer-authored action.

**Investigated and ruled out:** the `[Code]` section (there wasn't one);
any post-install script/batch file (none exists); Windows-service or
scheduled-task creation (this installer never creates either); the
Inno Setup GUI itself (a normal window throughout — confirmed by
inspecting `ubads_agent.iss`'s `[Setup]` section, which sets no console
flags and Inno Setup's own compiler/wizard are never console-mode).

**Fix:** the `[Run]` section was removed entirely from `ubads_agent.iss`
— not just the checkbox's default state changed. Confirmed by recompiling
and checking the compiler's own parse trace: it contains zero references
to a `[Run]` section at all. Structurally, this installer can never launch
anything after installation, under any checkbox state, silent or
interactive install — there is nothing left in the script that could.

**Preserved (verified for real, this phase, from the rebuilt `.exe`):**
- `-h` — prints argparse usage correctly.
- `--identity` — creates persistent state and returns the same
  `endpoint_id` on a second run (unchanged from Phase 13/14).
- `--status` — reaches the real local backend (`reachable`/`ready`).
- `--collect` — runs a full cycle: honestly warns when no enrollment key
  is configured, honestly reports `SECURITY_LOG_ACCESS_DENIED` per
  category, exits non-zero. All exactly as designed, unchanged.

The Start Menu "UBADS Agent Status" shortcut (`--status`) is unaffected
and unchanged — clicking it still shows a console window, which is
correct and expected: that is the user *deliberately* asking to see
status output, not an installer-triggered flash.

**NOT PRODUCTION READY / remaining limitation:** the literal "run the
rebuilt installer's GUI wizard and watch for any window flash" step was
not performed in this tool session (no Administrator rights here, and no
interactive desktop session available to this Claude Code tool — the same
constraint documented throughout this project for anything requiring
elevation or a GUI). What was verified instead: the compiled installer
structurally contains no post-install launch capability at all (a
deterministic property of the Inno Setup format, not something that needs
watching a wizard to confirm), and the packaged executable's full CLI
still works correctly when run directly. Please re-run the rebuilt
`agent/dist/UBADS-Agent-Setup.exe` and confirm no window appears — this is
the one remaining manual confirmation step.

### Installed agent configuration

The portal's approved endpoint installer supplies the one-time enrollment
authorization. On successful enrollment, the agent writes its trusted
configuration to `%ProgramData%\UBADS\Agent\config\agent.json`; ordinary
process environment variables and executable-adjacent `.env` files cannot
redirect an installed production agent. Manual shared-key setup remains a
development-only workflow. See the current Configuration section above for
the production schema and transport requirements.

### Per-endpoint identity and credentials — verified for real, twice

Each installed agent keeps its own stable identity and obtains its own
unique credential — never a shared one — exactly as Phase 11 designed and
Phase 13 made persistent across restarts. This phase verified it holds
across **separate installations**, not just separate runs of one install:

Two independent "installations" were simulated (two separate copies of
`ubads-agent.exe`, each with its own isolated `LOCALAPPDATA` and its own
`.env` pointing at the real local backend with the real shared enrollment
key):

| | Install 1 | Install 2 |
|---|---|---|
| `endpoint_id` | `bd3591d5-...` | `fcb9f22e-...` |
| Credential | `vnJOHKq6...` | `iL7K15Jf...` |

Both enrolled successfully against the real backend, each receiving a
**different** credential for the **same** shared enrollment key — proving
the enrollment key only ever bootstraps a unique per-endpoint credential,
never becomes a shared one for ongoing operation. `GET /api/endpoints`
listed all three endpoints (these two plus the real one) distinctly. The
test enrollments and their data were removed from the real database
afterward.

### Multi-endpoint dashboard visibility — verified for real

Using the same two simulated endpoints, one real test event was ingested
under Install 2's credential. `GET /api/events?endpoint_id=<install-2-id>`
returned exactly that one event; `GET /api/events?endpoint_id=<the other
endpoint>` did not include it, and vice versa — see backend/README.md
"Multi-endpoint dashboard support" for the exact verification. The
frontend's Events page (Phase 14) now has a real "Enrolled Endpoint"
filter, sourced from `GET /api/endpoints`, wired to this exact
`endpoint_id` field — not the older, self-reported computer-name filter,
which stays for display but is no longer the only way to separate
endpoints.

### Uninstalling

Use "Uninstall UBADS Agent" from the Start Menu, or the normal
Add/Remove Programs entry. This removes only the installed program files
— it does **not** delete `%ProgramData%\UBADS\Agent\` (the endpoint's
identity, credential, checkpoint, and buffer). Legacy LocalAppData state is also left untouched. The updated installer
blocks an existing installation until a supported migration is available;
do not manually delete or copy endpoint state as a workaround.

### LOCAL VERIFIED vs. PRODUCTION READY

**LOCAL VERIFIED** (this phase, for real): the installer builds and
compiles; installing it would place real files (verified by inspecting
what Inno Setup packages — the exact same `ubads-agent.exe` and
`env.example` already smoke-tested); the packaged executable enrolls,
obtains a unique credential, and reports its status against a real
backend; two independent installs get independent identities/credentials;
events from two endpoints are correctly kept apart end-to-end through the
real backend API and the frontend's new filter; the download button's
disabled-by-default behavior is unchanged and un-fakeable.

**NOT PRODUCTION READY:**
- The installer and the `.exe` inside it are **unsigned**. Windows
  SmartScreen and/or antivirus software will very likely warn on both —
  expected and disclosed, not hidden, and not something this phase
  attempts to suppress or bypass.
- Nothing is hosted anywhere. `VITE_AGENT_INSTALLER_URL` still has no real
  value by default. A local/dev download path now exists (Phase 14A —
  see "Downloading the local installer from the frontend" below), but it
  is explicitly a `npm run dev`-only fallback, stripped from any
  production build.
- The actual, literal "double-click the installer with a UAC prompt"
  installation step was not run in this session (this tool session has no
  Administrator rights — the same constraint documented throughout Phase
  11/12); everything downstream of that step (the exact files it would
  place, and the agent's real behavior once run) was verified directly and
  is not simulated or assumed.
- No HTTPS/TLS backend has actually been stood up to test against; only
  the code-level capability was confirmed.
- No Azure hosting, code signing, or release process exists — all
  explicitly PLANNED, not implemented.

## Downloading the local installer from the frontend (Phase 14A)

**Status: IMPLEMENTED, LOCALLY VERIFIED.** The Endpoint Enrollment page's
"Download Windows Agent" button can now actually download the real
compiled `UBADS-Agent-Setup.exe` during local development — see
`frontend/src/pages/EndpointEnrollment.jsx` and
[`frontend/README.md`](../frontend/README.md).

**How it works:**
- If `VITE_AGENT_INSTALLER_URL` is set, the button uses that URL —
  unchanged, this is the intended production path (not implemented yet).
- If it is **not** set, and the frontend is running under `npm run dev`
  (`import.meta.env.DEV`, Vite's own built-in flag — never a hard-coded
  environment name), the button serves the real installer from
  `frontend/public/downloads/UBADS-Agent-Setup.exe` and the page shows an
  explicit warning label: "Local development build ... not a hosted
  production release."
- In a production build (`npm run build`), neither condition above
  applies without a real `VITE_AGENT_INSTALLER_URL` — the button stays
  disabled, exactly as before Phase 14A. `frontend/vite.config.js`
  additionally deletes the `downloads/` folder from the build output
  entirely, so the unsigned dev installer is never physically present in
  a production bundle, not just unlinked from the UI.

**Populating the local download folder** (a rebuildable artifact, never
committed — see `frontend/public/downloads/README.md`):
```powershell
Copy-Item agent\dist\UBADS-Agent-Setup.exe frontend\public\downloads\UBADS-Agent-Setup.exe
```

**Verified for real, this phase:**
- The file in `frontend/public/downloads/` is byte-for-byte identical
  (SHA-256 hash compared) to `agent/dist/UBADS-Agent-Setup.exe` — not a
  placeholder.
- `curl http://localhost:5173/downloads/UBADS-Agent-Setup.exe` returned
  HTTP 200 with exactly 20,465,120 bytes; the downloaded bytes' SHA-256
  hash matched the source file exactly.
- `npm run build` completed successfully, and its `dist/` output contains
  **no** `downloads/` folder and no `.exe` file at all.
- `frontend/public/downloads/` itself (the dev-mode source) was
  unaffected by running a production build.

**NOT PRODUCTION READY:** this is explicitly a local development
convenience. The installer served this way is still unsigned; nothing is
hosted for a real end user to reach; a real deployment must set
`VITE_AGENT_INSTALLER_URL` to an actual hosted, ideally signed, release
artifact.

## Tests

```powershell
pytest tests/agent
```

Every test mocks Windows Event Log access and HTTP calls — none require
real credentials, a real backend, or a real Windows machine, and none
write to `agent/.state/` for real (redirected to a throwaway temp
directory via the `agent_tmp_dir` fixture in `tests/agent/conftest.py`).

## IMPLEMENTED / VERIFIED / NOT YET VERIFIED / PLANNED

- **IMPLEMENTED & VERIFIED** (real backend + real Windows Event Log):
  per-agent credential enrollment and authentication; persistent,
  restart-surviving collection checkpoint that advances only after
  confirmed delivery; honest `SECURITY_LOG_ACCESS_DENIED` reporting;
  endpoint-attributed ingestion; failed-upload buffering without cursor
  advance; real Windows authentication (4624), process (4688), and file
  (4656/4660/4663) events collected end-to-end (see root README Phase
  12C/12D); local Windows `.exe` packaging (Phase 13 — PyInstaller), with
  frozen-mode persistent state/config resolution verified for real,
  including a real `--collect` enrollment cycle from the built `.exe`;
  local Windows installer/uninstaller (Phase 14 — Inno Setup,
  `UBADS-Agent-Setup.exe`); two independently "installed" copies of the
  agent obtaining distinct identities and distinct credentials from the
  same enrollment key, verified for real; multi-endpoint event separation
  verified end-to-end through the real backend API and the frontend's new
  per-endpoint filter.
- **NOT YET VERIFIED**: real device-activity (6416) collection; long-running
  `--run` behavior over many hours or days; multi-day real dataset
  collection; log-rollover recovery against a real cleared Windows log
  (unit-tested, not exercised against a real rollover); Security-log
  content collection specifically from the packaged/installed executable
  under Administrator; the packaged executable or installer running on a
  machine other than the one that built it; the literal
  installer-with-UAC-prompt install step (this session has no
  Administrator rights — everything downstream of it was verified
  directly instead, see "LOCAL VERIFIED vs. PRODUCTION READY" above); any
  antivirus reaction to the unsigned executables; HTTPS against a real
  TLS-terminated backend (the code path is unchanged and `requests`
  supports it, but no such backend has been stood up to test against).
- **PLANNED (later phases)**: Windows service installation (design only,
  never auto-installed), code signing, a hosted/published release
  download URL (Azure Blob Storage / GitHub Releases or similar — no
  Azure work has started), credential rotation policy, a richer
  fleet-management UI beyond a per-endpoint events filter, machine
  learning / anomaly detection.

## Phase 16 Stage 3 - Automatic operation

Commands (all in addition to the existing `--identity --status --collect --run --setup`):

| Command | What it does |
|---|---|
| `--background` | Same loop as `--run`, but no console; logs to the selected agent log directory (rotating, 1 MB x 3). The windowless build is `ubads-agent-bg.exe`. |
| `--install-task` / `--uninstall-task` | Create / remove the Task Scheduler task "UBADS Agent". |
| `--start` / `--stop` / `--restart` | Start (via the task if installed, otherwise a hidden process), stop cleanly (finishes the current cycle), or restart. |
| `--status` | Now also reports `agent_process` (running, pid), `scheduled_task`, and the log file path. |

**Why the task runs as the installing user, not SYSTEM.** Nothing needs SYSTEM:
the Security log is readable by an Administrator (an admin's task started from
an elevated `--install-task` runs elevated with no UAC prompt) or by Event Log
Readers members; the credential is DPAPI-protected to that user. SYSTEM would
have a different profile (so a different identity/credential/checkpoint
location and DPAPI scope) and more privilege than needed. **Trade-off:** the
task starts at that user's *sign-in*, not at boot. If the computer reboots, the
agent resumes after the user signs in (with a 30 s delay for the network).

**Credential protection and recovery.** `credentials.json` holds the credential
encrypted with Windows DPAPI (user scope + application entropy). A missing file
means the endpoint is not enrolled. A corrupt, inaccessible, or undecryptable
file is a separate error: the agent stops and does not automatically enroll or
replace it. Preserve the file and contact an administrator to verify the
endpoint's backend record and coordinate credential revocation and explicit
recovery. The administrator should stop the agent, retain a protected backup
of its identity and credential files, verify the endpoint record, and revoke
the server credential before archiving/removing only the corrupt local
credential and authorizing a fresh endpoint-specific enrollment. Do not clear
a valid credential or retry enrollment as the first recovery step. New
enrollment writes do not replace an existing credential. Older plain-text
files are upgraded atomically after they are read successfully.

**Single instance.** An OS file lock in the state folder (`agent.lock`) is held
by the running loop; a second `--run/--background` exits with code 3, and
`--collect` declines while the agent is running. The lock disappears if the
process crashes or is killed.

**Resilience.** A failed cycle (network down, etc.) is logged and retried at the
next interval; unsent events stay buffered and the checkpoint only advances after
a confirmed upload (duplicates are rejected server-side). Pending-buffer updates
are written to a protected temporary file in the same directory, flushed and
closed before atomic replacement, so a failed write or replacement leaves the
previous buffer intact.

`UBADS_STATE_DIR` (environment variable) relocates the state folder - used for
isolated testing.

## Phase 17 Stage 4E - enrolling installer (isolated TEST build first)

`installer/ubads_agent.iss` now enrolls the computer using the one-time code in its own file name, then
schedules and starts the agent (see `docs/phase17-stage4e-installer.md`). Build variants:

```powershell
cd agent
# 1. executables into a SEPARATE folder (agent\dist is what the current production installer was built from)
..\.venv\Scripts\python.exe -m PyInstaller ubads_agent.spec --noconfirm --distpath dist-test --workpath build-test
# 2. isolated per-user TEST installer (no UAC; own AppId, folders, state dir and task "UBADS Agent TEST")
& "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe" /DTESTBUILD /DDistDir=..\dist-test installer\ubads_agent.iss
# 3. the same test build but requesting UAC (for the manual elevation check)
& "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe" /DTESTBUILD_ELEVATED /DDistDir=..\dist-test installer\ubads_agent.iss
```

Real installer tests (opt-in; they install the TEST build under `%LOCALAPPDATA%\UBADS-TEST` and use the
task `UBADS Agent TEST`, never the real agent):

```powershell
$env:UBADS_RUN_INSTALLER_TESTS = "1"; .venv\Scripts\python.exe -m pytest tests\installer -q -s
```

Manual UAC check: `python tests/installer/manual_elevated_check.py prepare | verify | cleanup`.

New agent commands used by the installer: `--verify-enrollment [--require-running]` (exit 0, or 40 not enrolled,
41 server unreachable, 42 credential rejected, 43 agent not running).
Note: do **not** run an installer with Inno's `/LOG` switch - the log records the setup file path, which carries the code.
