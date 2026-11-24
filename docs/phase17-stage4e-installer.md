# Stage 4E - Installer integration: architecture, sequence and verification plan

## 1. Existing pieces (inspected)

* `agent/installer/ubads_agent.iss`: Inno Setup 6 (Unicode), `PrivilegesRequired=admin`, installs `ubads-agent.exe`, `ubads-agent-bg.exe`, `.env.example`; no `[Run]`, no `[Code]`; `InfoAfterFile` with manual steps; uninstall does **not** remove the scheduled task.
* Agent (Stage 4D): `--enroll-from-process <PID>` (PID must be an ancestor; code is read from that process's executable file name), exit codes 0/2/3/10-16/20-24/30/31, then `--install-task`, `--start`.
* Backend (4A-4C/Stage 5 Phase 4E): `POST /api/endpoint-requests/{id}/enrollment-package` returns the configured installer file only after owner/approval checks; production reads from a private Azure Blob via managed identity. Its single-use enrollment code is carried by the response filename; the code is never placed in a URL, application log, or audit record.
* The build outputs `agent/dist/*` are what the current production `UBADS-Agent-Setup.exe` was compiled from. **They are not touched**: the isolated build uses `agent/dist-test/` and writes `agent/dist-test/UBADS-Agent-Setup-TEST.exe`.

## 2. Installation sequence (what the installer will do)

Executed in Inno's `ssPostInstall` step, after the files are copied. The installer never reads, stores, logs or forwards the enrollment code; it only passes **its own process id** (not a secret) to the agent.

| # | Step | Failure behaviour |
|---|---|---|
| 1 | Prerequisites: Windows 10+ (Inno `MinVersion`), 64-bit, files present. | Setup refuses to start. |
| 2 | Validate authorization input: does *this installer's file name* contain `--ubads1.`? (a yes/no test; the value is not kept). | No code -> legacy "files only" install; nothing is enrolled, no task, no start; the finish page says how to get a proper installer. |
| 3 | Install agent files (Inno). | Inno rolls back on error. |
| 4 | `ubads-agent.exe --enroll-from-process <PID>` (hidden, waited). | Exit code mapped to a plain message. **No task, no start, no success page.** Exit 3 (already enrolled): nothing is touched, existing credential kept. |
| 5 | `ubads-agent.exe --verify-enrollment` : credential present, decrypts, server accepts it (authenticated heartbeat). | Stop; report; do not schedule. |
| 6 | `ubads-agent.exe --install-task`. | Report; enrollment kept, agent not started. |
| 7 | `ubads-agent.exe --start`. | Report. |
| 8 | `ubads-agent.exe --verify-enrollment --require-running`: agent process alive + backend accepts the credential. | Report. |
| 9 | Success is shown **only** if 4-8 all returned 0, including the approved scope read from the agent's non-secret config. | - |

Every step appends a **non-secret** line (step, exit code, time) to `installer.log` in the agent's logs folder, and a machine-readable `installer-result.json` is written. Neither contains the code, the credential or the installer file path.

Uninstall: stops the agent, removes the scheduled task (new `[UninstallRun]`), removes program files. The local endpoint identity/credential are **kept** (a later reinstall keeps its identity); the uninstall page says an administrator should revoke the endpoint if the machine is retired.

## 3. How the code reaches the agent (no argv / env / file / registry / log)

1. The code exists only in the installer's file name (put there by the backend response).
2. The installer passes `GetCurrentProcessId()`.
3. The agent checks that PID is one of its ancestors, reads that process's image path (`QueryFullProcessImageNameW`) and extracts the code from the file name.

Known exposure that is outside the installer's control and is documented to users: the downloaded file name (browser history / Downloads folder) and **Inno's optional `/LOG` switch, which records the setup exe path**. We never enable logging; the test suite checks that a normal run writes no such log and that the code is absent from the install folder, state folder, uninstall registry key, scheduled-task XML and every process command line sampled during installation.

## 4. The elevation / relaunch question (not assumed)

Unknowns to be answered by experiment, in this order:

1. When Inno extracts and re-launches itself, what is the **file name and PID** of the process whose PID `GetCurrentProcessId()` returns inside `[Code]` - and is the code still in its image path?
2. Is that process in the agent's ancestor chain (the agent is started by `Exec` from that process)?
3. Does the same hold when Setup runs **elevated through UAC**?

(1) and (2) are testable without UAC with a per-user (`PrivilegesRequired=lowest`) build, because Inno relaunches itself from a temp folder in both modes. (3) needs a human to approve UAC; I cannot and will not click or suppress it. A second, clearly named **elevated test build** is produced for that, and it records a non-secret diagnostic (`is_admin`, whether the image-path name carried a code, ancestor count) so one manual run answers the question. If any step fails, stop and design an alternative rather than relaxing the ancestry check.

## 5. Isolation of the test build

* Different Inno `AppId`, name "(TEST BUILD)", install dir `%LOCALAPPDATA%\UBADS-TEST\App`, output `agent/dist-test/UBADS-Agent-Setup-TEST.exe`.
* A `ubads-agent.profile` file written next to the installed exe redirects the agent's **state folder** (`%LOCALAPPDATA%\UBADS-TEST\Agent\.state`) and **scheduled-task name** (`UBADS Agent TEST`). It is read only when present, so production installs are unchanged. The existing `UBADS Agent` task and `%LOCALAPPDATA%\UBADS\Agent` are never referenced.
* The test backend is a throwaway process on its own port with a temp database; the "downloaded" installer comes from that backend's `enrollment-package` route (so the whole portal -> installer -> agent -> backend chain runs).

## 6. Test matrix

Automated, genuinely executed on Windows (per-user, no UAC): compile; packaged exes; fresh install with a real code; enrollment, DPAPI credential, task arguments/name, process running, backend heartbeat + scoped ingestion of a labelled fixture; second run (already enrolled, nothing overwritten); expired / invalid / revoked / backend-down / no-code installs (no task, no credential, no success); uninstall; leak scan; process-command-line sampling.
Needs a human (UAC): the elevated build run.
Not executed: anything involving a second Windows user; code signing; SmartScreen behaviour.
