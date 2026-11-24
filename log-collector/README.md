# Log Collector — Phase 2 + Phase 3 + Phase 4

**Status:** Implemented — reads real Windows Security event log entries
from the local machine across four categories (authentication, file
activity, process activity, device activity), normalizes them, validates
them, and stores them in a local SQLite database (deduplicated). Does not
yet call the `backend/` API directly, or do any ML/feature engineering —
those are later phases.

## Pipeline

```
Windows Computer
      ↓  (real Security-log events, per category)
REAL WINDOWS EVENT
        ↓  win32evtlog.EvtQuery/EvtRender      (collector.py)
RAW EVENT XML
        ↓  parse_event_xml / normalize_event   (event_parser.py)
NORMALIZED EVENT (dict, event_category set)
        ↓  validate_event                      (validation.py)
VALIDATED EVENT
        ↓  insert_event (dedup by event_uid)   (storage.py)
SQLITE (data/app.db, table "events")
        ↓
READY FOR FUTURE FEATURE ENGINEERING (Phase 5+)
```

Phase 4 integrates entirely inside the existing Phase 2/3 pipeline — no new
top-level module was introduced. `collector.py` gained a `--categories`
flag; `event_parser.py`'s single `normalize_event()` entry point now
dispatches to a category-specific normalizer internally; `storage.py`'s
single `events` table gained new nullable columns via a non-destructive
migration (see "Database schema" below). `validation.py` is unchanged and
reused as-is — its required-field rules already applied generically.

## Authorization — read this first

This tool reads security-relevant event log data from whatever Windows
machine it is run on. **Only run it on a computer you are explicitly
authorized to collect security/activity logs from** (e.g. your own
development machine for this research project, or a machine where you have
documented permission).

This project is **not** spyware and is not intended to run covertly or
collect data from machines without the owner/operator's knowledge and
consent. It does not collect passwords, password hashes, keystrokes,
screenshots, document contents, browser data, or private messages — only
the authentication-related event metadata described below.

## Event categories

Select which categories to collect with `--categories` (comma-separated).
Default is `authentication` only, unchanged from Phase 2/3 — you opt in to
the others explicitly.

| Category | `--categories` value | Event IDs | Audit policy prerequisite |
|---|---|---|---|
| Authentication | `authentication` | 4624, 4625, 4634, 4647 | "Logon" (Success+Failure, for 4624/4625) and "Logoff" (Success, for 4634/4647). **Usually** audited by default on Windows Server / domain-joined / Group-Policy-managed machines — but NOT guaranteed on a standalone Windows Home machine with no audit baseline applied, where both subcategories can default to "No Auditing" (Phase 12C finding). Run `scripts\enable_authentication_audit.ps1` as Administrator if `auditpol /get /subcategory:"Logon","Logoff"` shows anything other than Success/Failure enabled. |
| File activity | `file_activity` | 4656, 4660, 4663 | "Audit Object Access → File System" **plus** a SACL on the specific folder(s) to monitor. Not enabled by default. Run `scripts\enable_file_activity_audit.ps1 -Path <folder>` as Administrator. |
| Process activity | `process_activity` | 4688 | "Audit Process Creation". Not enabled by default. Run `scripts\enable_process_and_device_audit.ps1 -Category process` as Administrator. |
| Device activity | `device_activity` | 6416 | "Audit PNP Activity". Not enabled by default. Run `scripts\enable_process_and_device_audit.ps1 -Category device` as Administrator. |

`download_related` is not a separate category to collect — it's a label
automatically applied to `file_activity` events whose path falls under a
configured downloads folder (see "Download activity" below).

Not every event ID will necessarily be present on every machine/configuration
— the collector handles that gracefully (it simply won't return events for
IDs that never occurred, aren't audited, or aren't enabled on this machine).

### Fields extracted (when present in the raw event)

Every normalized event carries the same full set of keys regardless of
category — fields that don't apply to a given category are `None`, never
guessed:

- **Common:** `event_id`, `event_record_id`, `event_type`, `event_category`,
  `timestamp`, `computer_name`, `username`, `domain`, `user_sid`,
  `account_type`, `raw_event_data`.
- **Authentication:** `logon_type`, `logon_type_description`, `source_ip`,
  `source_port`, `workstation_name`, `subject_username`, `subject_domain`,
  `failure_reason` (4625 only).
- **File activity:** `file_path`, `file_extension`, `object_type`,
  `file_action` (`handle_requested` / `accessed` / `deleted`),
  `process_name`, `access_list_raw`.
- **Process activity:** `process_name`, `process_id`, `parent_process_id`,
  `parent_process_name`.
- **Device activity:** `device_id`, `device_description`, `device_class`,
  `device_action` (always `"connected"` — see "Device/USB activity" below).

### Account type handling

Many Security events come from non-human accounts (`SYSTEM`,
`LOCAL SERVICE`, `NETWORK SERVICE`, computer accounts ending in `$`).
`account_type` is a best-effort label (`system`, `local_service`,
`network_service`, `computer_account`, `human_or_unknown`, `unknown`)
based on the event's SID/username. **Deciding which events represent real
human behavior for analysis purposes is deferred to a later phase** — this
phase only classifies and preserves the raw data.

## File activity

Windows only produces 4656/4660/4663 events for objects that have an
**explicit audit rule (SACL)** — enabling the global "File System" audit
subcategory alone does nothing by itself; it only allows auditing to occur
where a SACL has been set. **This project does NOT enable this on your
whole computer.** Use the provided script to configure it for exactly one
folder you choose:

```powershell
# Run PowerShell as Administrator, then:
cd log-collector\scripts
.\enable_file_activity_audit.ps1 -Path "C:\Users\you\Documents\UBADS_TestFolder"
```

This script (see its full source for exact commands) does exactly two
things: enables the "File System" audit subcategory globally (a
prerequisite switch, audits nothing by itself), and adds an audit rule to
the one folder path you pass in — no other folder is affected. It prompts
for confirmation before making any change.

**What Windows generates:** 4656 (handle to object requested), 4663
(attempt to access an object), 4660 (object deleted) — each includes
`ObjectName` (full file path), `ObjectType`, `SubjectUserName`/`Sid`,
`ProcessName` (the process that touched the file), and `AccessList` (a
Windows-formatted access-rights string).

**Known limitation — action granularity:** Windows exposes fine-grained
detail (created vs. modified vs. read) only by decoding `AccessMask`, which
Windows expresses via localized message-table strings (`%%4416` etc.) that
are unreliable to decode generically across Windows versions/locales. This
project does **not** attempt that decoding — `file_action` only reflects
which event ID fired (`handle_requested` / `accessed` / `deleted`), and the
raw `AccessList` string is preserved as-is (`access_list_raw`) for anyone
who wants to decode it further later. This is a deliberate, documented
limitation, not an oversight.

**Not collected:** file contents are never read, copied, or uploaded —
only the metadata Windows itself logs.

## Process activity

**What Windows generates:** event 4688 ("a new process has been created")
whenever any process starts, once "Audit Process Creation" is enabled:

```powershell
# Run PowerShell as Administrator:
cd log-collector\scripts
.\enable_process_and_device_audit.ps1 -Category process
```

Unlike file activity, this is a simple global on/off switch (no per-object
SACL needed) and is a commonly recommended baseline Windows security
setting.

**Fields captured:** `process_name`/`process_id` (the new process),
`parent_process_id`/`parent_process_name` (what launched it),
`username`/`domain`/`user_sid` (the account context).

**Command-line privacy note:** Windows only includes a `CommandLine` field
in 4688 if the separate "Include command line in process creation events"
policy is enabled — it is **not** enabled by default, and this project does
**not** enable it for you. If your machine already has it enabled
(inherited from an existing policy), `CommandLine` will appear inside
`raw_event_data` (since that always preserves every field Windows
provides) but is **not** promoted to its own column, since command lines
can incidentally contain sensitive arguments. If you don't want this data
captured at all, leave that policy disabled (its default state).

## Device/USB activity

**What Windows generates:** event 6416 ("a new external device was
recognized by the system"), once "Audit PNP Activity" is enabled:

```powershell
# Run PowerShell as Administrator:
cd log-collector\scripts
.\enable_process_and_device_audit.ps1 -Category device
```

**Fields captured:** `device_id`, `device_description`, `device_class`,
`username`/`domain`/`user_sid` (the session context recognizing the
device, when available — PNP recognition can occur before user logon,
in which case these may be `None`).

**Known limitation — connect only:** the "PNP Activity" audit subcategory
only documents a device-recognized/connected event (6416). There is no
equally well-documented, version-independent Security-log event for
device *removal* in the same subcategory, so **disconnect/removal
detection is not implemented in this phase** — this is stated here rather
than approximated with an unverified event ID.

**Not collected:** the contents of any connected device are never read.

## Download activity

**Important distinction, as required by this phase:**

- **(a) Directly observed:** the underlying `file_activity` event itself
  (4656/4663/4660) — Windows really did report file activity at that path.
- **(b) Inferred by this project:** if that path falls under a folder you
  configure (`MONITORED_DOWNLOAD_FOLDER` in `config/.env`, or
  `--downloads-folder`), the event's `event_category` is relabeled
  `download_related` instead of `file_activity`. This is a **location-based
  guess**, not a confirmed download — a file manually moved or saved there
  by any means looks identical to a browser download from this signal
  alone. This project does **not** claim Windows Security auditing provides
  a complete or authoritative list of browser downloads.
- **(c) Requires browser/application telemetry (out of scope):**
  confirming a file specifically came from a browser download (vs. any
  other way a file could land in that folder) would require
  browser-specific instrumentation (e.g. a browser extension or download
  history API). This project does **not** install browser extensions or
  read browser history, per this phase's instructions.

## Safety / no silent changes

- This project's code never runs `auditpol` or modifies any SACL itself —
  every audit-policy change requires you to run one of the scripts in
  `log-collector/scripts/` yourself, as Administrator, and each script
  prints exactly what it's about to change and asks for confirmation first.
- Nothing here disables any existing Windows security feature or bypasses
  any security control.
- The collector has no stealth or persistence mechanism — it runs once,
  visibly, when you invoke it, and does nothing in the background.

## Why pywin32 / the modern Event Log API

The collector uses `win32evtlog.EvtQuery` / `EvtNext` / `EvtRender`
(pywin32's binding to the modern Windows Event Log API), not the older
`ReadEventLog` API. The older API returns each event's variable fields as a
positional list of strings with no names attached, so decoding it correctly
requires hardcoding field order per event ID — fragile and version-specific.
The modern API renders each event as XML with every field explicitly named
(`TargetUserName`, `LogonType`, `IpAddress`, ...), which is what
`event_parser.py` reads by name. It also supports querying the log with an
XPath filter, so we only ever pull the specific event IDs and count we ask
for — never the whole log.

## Files

- `collector.py` — CLI entry point/orchestrator; queries the Windows
  Security log, then normalizes, validates, and stores each event, and
  reports a summary. Contains no SQL/ORM logic itself.
- `event_parser.py` — the **normalizer**: pure parsing/normalization logic
  (no pywin32 dependency, no I/O — unit-tested independently).
- `validation.py` — required-vs-optional field validation for normalized
  events, and UTC timestamp parsing.
- `storage.py` — the **repository layer**: SQLAlchemy engine/session,
  the `EventRecord` table definition, insert-with-deduplication, and
  read-back helpers. This is the only file that would need to change to
  move from local SQLite to an Azure-hosted database later.
- `requirements.txt` — `pywin32`, `sqlalchemy`, `python-dotenv`.
- `scripts/enable_file_activity_audit.ps1` — configures Object Access
  auditing for ONE explicitly named test folder (must be run manually, as
  Administrator).
- `scripts/enable_process_and_device_audit.ps1` — enables the
  "Process Creation" and/or "Plug and Play Events" audit subcategories
  (must be run manually, as Administrator).
- `scripts/enable_authentication_audit.ps1` — enables the "Logon"
  (Success+Failure) and "Logoff" (Success) audit subcategories, needed
  when they default to "No Auditing" (must be run manually, as
  Administrator; see "Known limitations").

## Install

From the project root:

```powershell
.venv\Scripts\Activate.ps1
pip install -r log-collector\requirements.txt
```

## Run — collect, normalize, validate, and store real events

```powershell
cd log-collector
python collector.py --limit 20
```

This queries the real local Security log (event IDs 4624/4625/4634/4647 by
default), normalizes and validates each event, stores new ones in
`data/app.db`, and prints a summary, e.g.:

```json
{
  "summary": {
    "collected": 20,
    "inserted": 20,
    "duplicates_skipped": 0,
    "validation_errors": 0
  },
  "validation_failures": []
}
```

### Preview without storing anything (old Phase 2 behavior)

```powershell
python collector.py --limit 20 --dry-run
```

Prints the normalized events as JSON but does not touch the database.

### Inspect what's actually stored

```powershell
python collector.py --show 20
```

Reads directly from the local SQLite database (no Windows Event Log call at
all) and prints the 20 most recent stored events.

### Collecting other categories

```powershell
# File activity (requires enable_file_activity_audit.ps1 to have been run for the folder you're testing)
python collector.py --categories file_activity --limit 20

# Process activity (requires enable_process_and_device_audit.ps1 -Category process)
python collector.py --categories process_activity --limit 20

# Device activity (requires enable_process_and_device_audit.ps1 -Category device)
python collector.py --categories device_activity --limit 20

# Multiple categories in one run
python collector.py --categories authentication,file_activity,process_activity,device_activity --limit 20
```

### Other options

```powershell
python collector.py --limit 5 --event-ids 4624,4625 --quiet   # low-level event-ID override, bypasses --categories
python collector.py --limit 20 --save                          # also writes a raw JSON copy to data/raw/
python collector.py --show 20 --category file_activity          # inspect only one stored category
python collector.py --limit 20 --downloads-folder "C:\Users\you\Downloads"  # override MONITORED_DOWNLOAD_FOLDER for this run
```

## Windows permissions and prerequisites

**Reading** the Security log (any category) normally requires one of:

- Running the terminal **as Administrator**, or
- Your account being a member of the built-in **"Event Log Readers"**
  local group (`lusrmgr.msc` → Groups → Event Log Readers → Add member),
  then signing out/in for the membership to take effect.

If you see an "Access denied" message from the collector, this is almost
always the cause — the collector detects this specific error and reports
it rather than failing silently.

To run as Administrator: right-click PowerShell/Windows Terminal → **Run as
administrator**, then re-activate the virtualenv and run the command above.

**Generating** events for any category requires its audit policy to be
enabled first (reading permission alone is not enough — if the policy
isn't enabled, Windows simply never writes those events, and the
collector will correctly report zero results):

| Category | Setup required |
|---|---|
| `authentication` | **Usually** already audited by default (Windows Server / domain / GPO-managed machines) — but verify first with `auditpol /get /subcategory:"Logon","Logoff"` (as Administrator; requires `SeSecurityPrivilege`, so it also fails without elevation). If either subcategory is not "Success and Failure"/"Success", run `scripts\enable_authentication_audit.ps1` as Administrator. See "Known limitations" — confirmed in Phase 12C to default to **off** on a standalone Windows Home machine. |
| `file_activity` | Run `scripts\enable_file_activity_audit.ps1 -Path <folder>` as Administrator. |
| `process_activity` | Run `scripts\enable_process_and_device_audit.ps1 -Category process` as Administrator. |
| `device_activity` | Run `scripts\enable_process_and_device_audit.ps1 -Category device` as Administrator. |

## Database schema

**Design choice: one generalized `events` table, not one table per
category.** All categories share most columns (timestamp, computer,
account fields, dedup key, raw data), and Phase 5 (feature engineering)
will need to correlate *across* categories for one user/machine/time
window (e.g. "logon, then file access, then process launch") — a single
table makes that a plain `WHERE`/`ORDER BY` query instead of joining N
separate tables. Category-specific columns are simply `NULL` for
categories that don't use them; this is judged an acceptable tradeoff for
a single-machine research database.

Table `events` in `data/app.db` (SQLite):

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK | Autoincrement surrogate key. |
| `event_uid` | TEXT, unique | Deduplication key — see below. |
| `event_id` | INTEGER | Windows event ID (4624, 4663, 4688, 6416, ...). |
| `event_record_id` | TEXT | Windows' own `EventRecordID` (sequence number in the log channel). |
| `event_type` | TEXT | e.g. `successful_logon`, `file_accessed`, `process_created`, `device_recognized`. |
| `event_category` | TEXT | `authentication` / `file_activity` / `process_activity` / `device_activity` / `download_related` / `uncategorized`. |
| `timestamp_utc` | DATETIME (tz-aware) | Event time, normalized to UTC. |
| `timestamp_raw` | TEXT | The original `SystemTime` string, unmodified. |
| `computer_name` | TEXT | Machine that recorded the event (this local computer). |
| `log_name` | TEXT | Which log channel it came from (e.g. `Security`). |
| `username`, `domain`, `user_sid` | TEXT, nullable | The account associated with the event (target user for logons; subject/acting user for file/process/device events). |
| `account_type` | TEXT, nullable | `system` / `local_service` / `network_service` / `computer_account` / `human_or_unknown` / `unknown`. |
| *(authentication)* `logon_type`, `logon_type_description` | INTEGER / TEXT, nullable | e.g. `2` / `interactive`. |
| *(authentication)* `source_ip`, `source_machine` | TEXT, nullable | `source_machine` is Windows' `WorkstationName` — the machine the logon *originated from*. |
| *(authentication)* `subject_username`, `subject_domain` | TEXT, nullable | The account that performed the action, when distinct from the target. |
| *(authentication)* `failure_reason` | TEXT, nullable | Only populated for event 4625. |
| *(file_activity)* `file_path`, `file_extension`, `object_type`, `file_action`, `process_name`, `access_list_raw` | TEXT, nullable | See "File activity" above for the action-granularity limitation. |
| *(process_activity)* `process_id`, `parent_process_id`, `parent_process_name` | TEXT, nullable | `process_name` is shared with file_activity's column (both mean "the process involved"). |
| *(device_activity)* `device_id`, `device_description`, `device_class`, `device_action` | TEXT, nullable | `device_action` is currently always `"connected"` (see limitation above). |
| `raw_event_data` | TEXT (JSON) | Every named field Windows provided, unmodified. |
| `collection_timestamp` | DATETIME (tz-aware) | When *our pipeline* processed this event (distinct from `timestamp_utc`). |

Required fields (an event failing these is **not** stored, and is reported
under `validation_failures`): `event_id`, `timestamp`, `computer_name`,
`event_type`. Every other field is optional — Windows may legitimately omit
it, in which case it's stored as `NULL`, never guessed. This validation
logic (`validation.py`) is unchanged from Phase 3 and applies identically
to every category.

### Upgrading an existing database

Schema changes are applied only through the controlled Alembic migration
command from the project root:

```powershell
python -m alembic upgrade head
```

The versioned migrations add legacy columns and indexes without dropping
tables or rows, and backfill the authentication category for legacy
authentication events. Collector startup checks that migrations have run;
it does not create, alter, or upgrade the schema.

## Deduplication strategy

Each event's `event_uid` is built from `(computer_name, log_name,
event_record_id)` — Windows' own `EventRecordID` is a sequential, unique
identifier per log channel per computer, so this reliably identifies one
real event. Before inserting, `storage.insert_event()` checks whether that
`event_uid` already exists and skips the insert if so (old data is never
deleted or overwritten — a duplicate is simply not re-inserted). If
`EventRecordID` were ever unavailable, it falls back to
`(computer_name, log_name, event_id, timestamp)`, which is documented as
not perfectly collision-proof but the best available substitute. Known
edge case: if the Windows log itself is cleared, `EventRecordID` numbering
restarts, which could theoretically collide with a previously seen ID —
acceptable for a local research tool and documented here rather than
silently ignored.

## Timestamp handling

Windows' `TimeCreated`/`SystemTime` field is already UTC (this is
documented Windows Event Log behavior — it is not "converted" from local
time by this project). `validation.parse_utc_timestamp()` parses that
string and attaches an explicit UTC timezone, and the result is stored in
`timestamp_utc`. The original unmodified string is also kept in
`timestamp_raw`, so the exact original value is always recoverable and no
conversion happens silently.

## Verifying the output is genuine

General procedure (applies to every category): trigger the real activity →
find it in Event Viewer → run the collector → confirm it's stored →
re-run to confirm deduplication → compare stored fields against Event
Viewer.

### Authentication

1. What Windows generates: events 4624/4625/4634/4647.
2. Where recorded: Event Viewer → **Windows Logs → Security**.
3. Trigger one: lock your screen and unlock it (or fail a login attempt).
4. Run: `python collector.py --categories authentication --limit 10`.
5. Stored metadata: `username`, `domain`, `logon_type`,
   `logon_type_description`, `source_ip`/`workstation_name`.
6. Limitations: none beyond the account-type caveat above.

### File activity

1. What Windows generates: events 4656/4663/4660, but **only** for objects
   with a SACL — see "File activity" section above for the one-time setup.
2. Where recorded: Event Viewer → **Windows Logs → Security**, filter by
   Event ID or by the object path.
3. Trigger it: after running `enable_file_activity_audit.ps1` for a test
   folder, create a file in it, edit it, then delete it.
4. Run: `python collector.py --categories file_activity --limit 20`.
5. Stored metadata: `file_path`, `file_extension`, `file_action`,
   `process_name` (the app that touched the file).
6. Limitations: action granularity is coarse (see above) — expect
   `handle_requested`/`accessed`/`deleted`, not precise create/modify
   distinctions.

### Process activity

1. What Windows generates: event 4688, once "Process Creation" auditing is
   enabled (see script above).
2. Where recorded: Event Viewer → **Windows Logs → Security**, Event ID
   4688.
3. Trigger it: launch any ordinary application (e.g. Notepad).
4. Run: `python collector.py --categories process_activity --limit 20`.
5. Stored metadata: `process_name`, `process_id`, `parent_process_name`,
   `parent_process_id`.
6. Limitations: `CommandLine` is only present if a separate, non-default
   Windows policy is enabled — see Privacy section.

### Device/USB activity

1. What Windows generates: event 6416, once "PNP Activity" auditing is
   enabled (see script above).
2. Where recorded: Event Viewer → **Windows Logs → Security**, Event ID
   6416.
3. Trigger it: connect an authorized USB device.
4. Run: `python collector.py --categories device_activity --limit 20`.
5. Stored metadata: `device_description`, `device_class`, `device_id`.
6. Limitations: connect-only — see "Device/USB activity" section above
   for why disconnect isn't covered.

### Confirming deduplication (any category)

Run the same collection command twice in a row. The second run's printed
summary should show `"inserted": 0` and `"duplicates_skipped"` equal to
however many of those events were already stored — proving the same real
event isn't re-inserted. Verified during Phase 3 testing on real machine
data, and the mechanism (`event_uid` from `EventRecordID`) is identical for
every category in Phase 4.

Every stored record's `log_name` field states which log channel it came
from, and `raw_event_data` preserves every field Windows itself reported,
so every stored row is traceable back to a real Event Viewer entry.

## Illustrative output format — not real collected data

```json
[
  {
    "event_id": 4624,
    "event_type": "successful_logon",
    "timestamp": "2026-01-01T09:15:00.000000Z",
    "computer_name": "<will be the real local computer name>",
    "username": "<real account name if present in the event>",
    "domain": "<real domain/computer name if present>",
    "user_sid": "<real SID if present>",
    "account_type": "human_or_unknown",
    "logon_type": 2,
    "logon_type_description": "interactive",
    "source_ip": null,
    "source_port": null,
    "workstation_name": "<real value if present>",
    "subject_username": null,
    "subject_domain": null,
    "failure_reason": null,
    "raw_event_data": { "...": "every named field Windows provided" },
    "_source": {
      "log_name": "Security",
      "computer_queried": "local machine",
      "collection_method": "Windows Event Log API (EvtQuery/EvtRender)"
    }
  }
]
```

This shape is illustrative only — actual values (usernames, timestamps,
SIDs, IPs) will be whatever your machine's real Security log contains, and
any field Windows didn't populate for a given event will be `null`. Stored
records (`--show`) follow the database schema table above instead — same
principle: illustrative shape, real values.

### Illustrative output — file_activity (not real collected data)

```json
{
  "event_id": 4663,
  "event_type": "file_accessed",
  "event_category": "file_activity",
  "file_path": "<real path if under an audited folder>",
  "file_extension": ".pdf",
  "file_action": "accessed",
  "process_name": "<real process path>",
  "username": "<real account name>"
}
```

### Illustrative output — process_activity (not real collected data)

```json
{
  "event_id": 4688,
  "event_type": "process_created",
  "event_category": "process_activity",
  "process_name": "<real process path>",
  "process_id": "<real PID, hex string as Windows reports it>",
  "parent_process_name": "<real parent process path>",
  "username": "<real account name>"
}
```

### Illustrative output — device_activity (not real collected data)

```json
{
  "event_id": 6416,
  "event_type": "device_recognized",
  "event_category": "device_activity",
  "device_description": "<real device description>",
  "device_class": "<real device class, e.g. DiskDrive>",
  "device_action": "connected"
}
```

## Privacy — what is and isn't stored

Reviewed against the fields Microsoft documents for every event ID this
project collects (4624/4625/4634/4647/4656/4660/4663/4688/6416): none of
them include passwords, password hashes, or any credential material by
default — Windows does not log that data for these audit events (the one
caveat is `CommandLine` on 4688, discussed in "Process activity" above,
which is opt-in and not enabled by this project).

This project does **not** collect or store: passwords, password hashes,
browser passwords, browser cookies, private messages, email contents,
document contents, photographs, keystrokes, screenshots, or
webcam/microphone data. It does not read file contents, copy files, or
upload files — only the metadata fields listed in the schema table above
are retained, the minimum needed for security/user-behavior analysis.

## Azure readiness (not implemented yet)

The storage layer stays isolated in `storage.py`. Backend and event storage
read the same `DATABASE_URL`; SQLite remains the local default, and
PostgreSQL URLs use the psycopg driver. Schema changes are versioned in the
root Alembic environment and must be applied with `python -m alembic upgrade
head` before running the collector or feature-engineering commands.
`storage.init_db()` now checks for an Alembic-managed database and does not
create or alter schema. No Azure resources or deployment code exist yet.

## Configuration (no hard-coded machine specifics)

Nothing in this phase hard-codes a username, computer name, path, or the
database location — all of it comes from `config/.env` or CLI flags:

- `DATABASE_URL` — shared SQLAlchemy database URL, SQLite by default.
- `MONITORED_DOWNLOAD_FOLDER` — optional, for `download_related`
  classification (new, Phase 4); overridable per-run via
  `--downloads-folder`.
- The file-activity test folder is passed explicitly to
  `enable_file_activity_audit.ps1 -Path <...>` — never assumed or
  hard-coded, so you always choose exactly which folder gets audited.

## Known limitations (Phase 4)

- **File action granularity:** cannot reliably distinguish created vs.
  modified vs. read — only which event ID fired. See "File activity".
- **Device disconnect:** not detected in this phase — connect/recognition
  only. See "Device/USB activity".

## Known limitation: authentication auditing is not always "on by default" (Phase 12C)

This project originally documented `authentication` (4624/4625/4634/4647)
as needing no audit-policy setup at all — a reasonable assumption on
Windows Server / domain-joined / Group-Policy-managed machines, where a
baseline security policy typically enables "Logon" and "Logoff" auditing.

Real Phase 12C verification on a **standalone Windows 11/10 Home** machine
(no Active Directory, no Group Policy) found this assumption did not hold:
`process_activity` and `file_activity` events were collected successfully
after their explicit setup scripts were run, but `authentication` produced
**zero** real events even with normal day-to-day logon/logoff activity
occurring, strongly suggesting the "Logon"/"Logoff" subcategories default
to "No Auditing" on this class of machine.

This is not a code bug: `collector.py`'s event IDs
(`CATEGORY_EVENT_IDS["authentication"] == [4624, 4625, 4634, 4647]`) and
`event_parser.py`'s normalization/categorization for all four IDs are
correct and unit-tested (see `tests/log_collector/test_collector.py` and
`test_event_parser.py`'s `test_normalize_logoff_event`/
`test_normalize_user_initiated_logoff_event`). The gap is the *assumed*
default audit policy, not the collector.

**Fix (manual, Administrator-run, not yet executed by this project):**
verify with `auditpol /get /subcategory:"Logon","Logoff"` (as
Administrator), and if either is not fully enabled, run
`scripts\enable_authentication_audit.ps1` as Administrator. See "Event
categories" above.

**Update (Phase 12D): this hypothesis was checked for real and disproven.**
Administrator verification confirmed `auditpol /get` already reports
`Logon: Success and Failure` and `Logoff: Success` — the audit policy was
already correctly enabled the whole time. The real, more likely cause,
found via read-only diagnostics that don't require Administrator
(`wevtutil gl Security` and a direct file-size check of
`Security.evtx`): the Security log is at exactly its configured maximum
size (20.0 MB of 20.0 MB, `retention: false` — i.e. it wraps/overwrites
its oldest events rather than growing or archiving). Now that Process
Creation auditing (4688, enabled in Phase 12B) is active, every single
process launch writes an event, which is a MUCH higher-frequency source
than Logon/Logoff (which only fire at actual sign-in/out/unlock moments).
On a full, wrapping log, that volume difference means low-frequency
Logon/Logoff events can be evicted between collection cycles faster than
a periodic `--collect` run catches them - the collector's "give me the
newest matching events" query is working correctly; there may simply be
none currently in the log to return. This has NOT yet been confirmed as
the definitive cause (that requires generating a real, fresh logon/logoff
event and re-collecting immediately afterward - see root README "Phase
12D" for the exact commands) and is documented here as the leading
hypothesis, not a certainty.
- **Download detection:** inferred by folder location only, not a
  confirmed "this came from a browser" signal. See "Download activity".
- **Process command lines:** only present if a separate, non-default
  Windows policy is already enabled on the machine; this project neither
  enables it nor promotes it to a first-class column.
- **Migration for existing databases:** the Phase 3→4 column migration
  backfills `event_category='authentication'` only for the four
  authentication event IDs; rows from any other pre-Phase-4 test data (e.g.
  events collected from a non-Security log during Phase 2/3 testing) keep
  `event_category = NULL` since their true category isn't known.

## What's NOT in Phase 4

- No forwarding of stored events to the `backend/` API (still separate).
- No ML / anomaly detection / risk scoring.
- No filtering of system vs. human accounts for analysis purposes — only
  labeling (`account_type`).
- No multi-computer collection, no Azure.
- No browser extensions, browser history reading, or confirmed-download
  detection beyond folder-location inference.
- No automatic enabling of any Windows audit policy — every prerequisite
  requires you to run a script manually, as Administrator, with explicit
  confirmation.

## Stage 4G - what raw event data is kept (privacy hardening)

`raw_event_data` is no longer a copy of every Windows `EventData` field. `event_sanitizer.py` keeps only an
**allowlist** of field names (who / what / when / where) and drops everything else, notably `CommandLine`,
which commonly carries passwords, tokens and keys when the "include command line in process creation events"
policy is on. Remaining free-text values additionally have secret-looking `key=value`, `--flag value`,
bearer/JWT and common token formats masked, and every value is capped at 4096 characters. It is applied in
`normalize_event()` (so the agent never buffers or uploads such data) **and** in `storage.insert_event()` (so the
database never persists it, whichever client sent it). Agents built before this change still send the old data; the
server removes it on arrival. Rebuild the agent executables to stop sending it at the source.
