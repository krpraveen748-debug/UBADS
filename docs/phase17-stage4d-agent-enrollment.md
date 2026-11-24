# Stage 4D - Windows agent enrollment: integration notes and installer interface

Scope: the AGENT side of one-time enrollment. The installer (Stage 4E) is not changed here.

## 1. What already exists (inspected) and how enrollment plugs in

| Area | Existing behaviour | Used by enrollment |
|---|---|---|
| CLI (`agent.py`) | Mutually exclusive commands (`--setup`, `--status`, `--collect`, `--run`, `--background`, `--start`, ...). | Three new commands are added to the same group; nothing existing changes. |
| Config (`config.py`, `user_config.py`) | pydantic settings read `.env` then the user-writable `agent.env` (written atomically). | After success, `BACKEND_URL`, `CATEGORIES` (the approved scope) and `ALLOW_INSECURE_HTTP` are written to `agent.env`. Never a secret. |
| Backend client (`backend_client.py`) | Single HTTP path, https-or-loopback policy, retries 5xx/network, classifies network errors. | New `redeem_enrollment()` (no shared key, **no retries**: a timeout after the server committed must not turn into a confusing "already used"). `BackendResult` gains `error_kind` / `error_code`. |
| Credential (`credential_store.py`) | DPAPI user-scope file `credentials.json`; atomic write; plaintext legacy upgrade. | Reused unchanged for storage; enrollment verifies a decrypt round-trip after saving. |
| Identity (`identity.py`) | Stable local UUID in `identity.json`. | Sent as the requested `endpoint_id` so identity stays stable; adopted only if the server returns a different id. |
| State dir / checkpoint / pending buffer / runtime state | Per-user `%LOCALAPPDATA%\UBADS\Agent\.state` (or `UBADS_STATE_DIR`). | Never touched by enrollment except identity/credential. |
| Existing enrollment (`_ensure_enrolled`, `--setup`) | Shared-key path. | Unchanged and still available. Enrollment by code **never** falls back to it. |
| Background/task (`task_scheduler.py`, `process_control.py`) | Task Scheduler + single-instance lock. | Enrollment starts nothing and never touches the task; 4E will call `--install-task` and `--start` afterwards. |

Existing installs are unaffected: enrollment by code refuses (exit 3) when a credential file already exists, without contacting the server, so a code is never spent on an enrolled machine.

## 2. Enrollment code handling

* The code only ever lives in a `SecretCode` object (mutable buffer; `repr/str` print `<redacted>`; zero-filled right after the single request). Python cannot guarantee wiping every transient `str` copy - this is best effort and documented.
* Inputs (all in memory, none on a command line / env var / config file / log):
  1. `--enroll` : hidden interactive prompt (`getpass`), for development.
  2. `--enroll-stdin` : exactly one line from a piped stdin (test harnesses).
  3. `--enroll-from-process PID` : **the installer interface** (below).
* Errors never include the code; free text from the server is passed through a redactor.

## 3. Order of operations (a failed enrollment never corrupts state)

1. Parse the code format locally (cheap, offline). Wrong format -> exit 2.
2. Refuse if a credential file exists (exit 3).
3. Choose the server: the address embedded in the code (or `--backend-url`); validate with the existing https-or-loopback policy; refuse a mismatch with an already-configured server.
4. **Pre-flight, before the server is contacted:** state folder writable, DPAPI protect/unprotect round-trip works, config file writable. A failure here (exit 30) spends nothing.
5. One redemption request (no retry, no shared key).
6. Validate the response *before* storing anything (UUID endpoint id, credential shape, scope is a non-empty subset of known categories).
7. Store: credential via DPAPI -> decrypt round-trip check -> identity -> `agent.env`. If the credential cannot be saved/verified the new file is removed (exit 31) and the message explains recovery.
8. Print success with the endpoint id and scope (never the credential or code).

## 4. Exit codes

| Code | Meaning |
|---|---|
| 0 | Enrolled |
| 2 | No/invalid code or bad usage |
| 3 | Already enrolled (nothing changed, server not contacted) |
| 10 | Invalid code |
| 11 | Expired or superseded code |
| 12 | Already-used code |
| 13 | Request revoked |
| 14 | Not authorised (request not approved / account / scope mismatch) |
| 15 | Rate limited - wait and retry |
| 16 | Endpoint id already registered |
| 20 | Network unavailable / timeout |
| 21 | TLS / certificate failure |
| 22 | Server error (5xx, incl. busy) |
| 23 | Malformed server response (nothing stored) |
| 24 | Backend configuration rejected (URL policy, server mismatch) |
| 30 | Local storage not usable (checked before contacting the server) |
| 31 | Server enrolled this machine but the credential could not be stored locally |

## 5. Installer interface for Stage 4E

The installer must not put the code on a command line, environment variable or file, and the agent must not either. The code is already in the installer's own file name (`UBADS-Agent-Setup--<code>.exe`, also seen as `...<code>.tmp` once Inno re-launches itself).

`ubads-agent.exe --enroll-from-process <PID>` where `<PID>` is the installer's process id (not a secret):

* the agent accepts the PID only if it is an **ancestor** of the agent process (the installer that launched it);
* it reads that process's executable path with `QueryFullProcessImageNameW` and extracts the code from the file name pattern `UBADS-Agent-Setup--<code>[ (n)].(exe|tmp)`;
* the code never touches a command line, environment, file or log.

4E sequence: `--enroll-from-process <pid>` -> on exit 0: `--install-task` -> `--start`; on any other exit show the mapped message and start nothing. To be verified in 4E: that Inno's elevated/re-launched process keeps the code in its image path.

## 6. Known limitations

* Python string memory cannot be fully wiped.
* A different-user DPAPI isolation test needs a second Windows account; it is covered by the OS guarantee plus entropy-binding tests, and explicitly marked as not executed.
* If the machine's network drops after the server commits, the code is spent (see the Stage 4 design, section 7).
