# Phase 17 / Stage 4 - Secure one-time endpoint enrollment: security design

Status: DESIGN (written before implementation). Scope: backend token model, redemption API, Windows agent and installer integration.
Out of scope: cloud hosting / deployment, email delivery, replacing the existing shared-key enrollment (it stays for operators).

## 1. Goal and security properties

An approved user installs the agent and it enrolls itself, with no typing, copy/paste or PowerShell. The server must guarantee:

| # | Property |
|---|---|
| P1 | Only the **approved requester** can obtain an enrollment code for their request. |
| P2 | A code works **once**, for **one** endpoint, within a **short** window, only while the request is still approved. |
| P3 | The database never holds a usable code: only a SHA-256 of its secret. Logs never contain it. |
| P4 | Redemption is **atomic**: concurrent redemptions yield exactly one credential. |
| P5 | The enrolled endpoint is bound to the approved user, organization and **monitoring scope**; the server enforces that scope on every upload. |
| P6 | Revoking a request kills unredeemed codes **and** the endpoint credential; revoked agents cannot upload. |
| P7 | The installer file is the same generic binary for everyone; it contains **no reusable secret**. |
| P8 | Existing endpoints, their credentials, the shared-key enrollment path, heartbeat and ingestion are unchanged. |

## 2. Threat model (what we defend against)

| Threat | Mitigation |
|---|---|
| Another user fetches / redeems someone's code | Code is minted only for the authenticated owner of an APPROVED request (404 for anyone else). A code is useless without also being an installer run on a machine; redemption checks the request, user and organization still match and are active. |
| Code stolen from disk / Downloads folder after use | Single-use: redeemed codes are dead. Unredeemed codes expire in `ENROLLMENT_CODE_TTL_MINUTES` (default 30). The installer deletes its working copy after use. |
| Code brute-forced | 256-bit random secret (`secrets.token_urlsafe(32)`); per-IP failure limiter on the redeem API; constant-time hash lookup by indexed unique digest. |
| Replay / race (two machines, double click) | Atomic conditional `UPDATE ... WHERE redeemed_at IS NULL AND superseded_at IS NULL AND revoked_at IS NULL AND expires_at > now`; only `rowcount == 1` proceeds. Whole redemption is one DB transaction. |
| DB leak | Only `sha256(secret)` stored; the secret is 256-bit so a fast hash is appropriate (same reasoning as agent credentials). |
| Scope tampering (agent or user asks for more) | Scope is **never read from the redeem request**. It is copied from the approved request at redemption time, compared with the scope pinned in the authorization row, and stored on the endpoint; ingestion rejects events outside it. |
| Host-header poisoning (attacker makes the embedded server URL point elsewhere) | The server URL embedded in a code comes only from `PUBLIC_BASE_URL` config, never from request headers. Production requires `https://`. The agent additionally refuses non-HTTPS non-loopback URLs. |
| Endpoint takeover via chosen `endpoint_id` | Redeem never overwrites: an `endpoint_id` that already exists is rejected (409). Server may assign its own id. |
| Revoke race (admin revokes while redeeming) | Redemption re-checks the request status inside the same transaction as the claim, using a conditional update on the request row; revoke uses the same row-level conditional update, so exactly one of them wins. |
| Token leakage via logs/analytics/URLs/browser storage | Code appears only (a) in the response `Content-Disposition` filename of one authenticated POST, (b) in the installer's own file name, (c) in a per-user temp file read once. Never in a URL, query string, JSON body returned to the page, localStorage/sessionStorage, server logs, audit detail or Inno logs. |
| Replacing the installer with a malicious one | Out of scope for this stage (no code signing yet): the download page shows the SHA-256; the build is documented as unsigned. |

## 3. Deliberate deviation from the brief: when the secret is created

The brief says the secret is generated at approval. A hashed-only secret cannot be shown later, so generating it at approval would force either (a) storing it recoverably (breaks P3) or (b) showing it to the **administrator** (a human in the middle of the secret - breaks P1). Therefore:

* **Approval creates the authorization**, transactionally with the status change (this already exists): requester, organization, approved scope, approval expiry (`APPROVAL_VALID_DAYS`), all on the request row, audited as `request.approved`.
* **The redeemable code is minted when the approved requester asks for the installer package** (`POST .../enrollment-package`). Hash stored, secret returned once, previous unredeemed codes for that request **superseded**.
* Page refresh / repeated clicks only mint a fresh code (and supersede the old one). They can never *consume* an authorization; only an agent redeeming does.

## 4. Lifecycle

### 4.1 Request status (admin decision + installation progress) - separate from connectivity

```
PENDING --approve--> APPROVED --mint package--> ENROLLMENT_PENDING --agent redeems--> ENROLLED
   |                    |   ^                         |  ^   (code expires/superseded -> back to APPROVED)
   |                    |   +-------------------------+  |
 reject                 +--approval window ends--> EXPIRED
   v                    revoke (from APPROVED / ENROLLMENT_PENDING / ENROLLED) --> REVOKED
REJECTED
```

* `INSTALLED` (Stage 3 name) is renamed **ENROLLED** (data migration; none exist in the real DB).
* Allowed for download/mint: `APPROVED`, `ENROLLMENT_PENDING` (within the approval window).
* EXPIRED/REJECTED/REVOKED are terminal.

### 4.2 Endpoint connectivity (derived, never stored on the request)

`online / stale / offline` from `last_seen` (existing). The UI shows `ONLINE`/`OFFLINE` beside, not instead of, the request status. "Approved" never implies "installed" or "online".

### 4.3 Code states (row in `enrollment_authorizations`)

`ACTIVE` (unredeemed, unexpired, not superseded/revoked) -> `REDEEMED` | `EXPIRED` (time) | `SUPERSEDED` (newer code minted) | `REVOKED` (request revoked).
Audit entries: `enrollment.code_issued`, `enrollment.code_superseded`, `enrollment.code_expired`, `enrollment.redeemed`, `enrollment.redeem_failed` (reason only), `request.revoked` (with `codes_revoked=N`, `credential_revoked`).

## 5. Data model (additive migrations only)

* `enrollment_authorizations` (exists, empty): add `revoked_at DATETIME`, `redeemed_from_ip VARCHAR`. `token_hash` already `NOT NULL UNIQUE`.
* `endpoints`: add `monitoring_scope VARCHAR NULL` (NULL = legacy/unrestricted), `enrolled_request_id VARCHAR NULL`.
* `endpoint_requests`: no new columns; status vocabulary extended; one-off `UPDATE ... SET status='ENROLLED' WHERE status='INSTALLED'`.
* Migration runs at backend start like the existing ones. **Before touching the real DB a backup is taken with the SQLite online-backup API**; migrations are first run on a copy.

## 6. Code format and delivery

Wire format (opaque to users): `ubads1.<base64url(PUBLIC_BASE_URL)>.<secret>` where `secret = token_urlsafe(32)` (43 chars). The server looks up `sha256(secret)`; the URL part is only a hint for the agent (the server does not trust it).

### Delivery to the installer without typing

`POST /api/endpoint-requests/{id}/enrollment-package` (owner only, bearer session, POST so it can never be triggered by a link/prefetch/refresh):

* mints the code, then streams the **generic installer bytes** with
  `Content-Disposition: attachment; filename="UBADS-Agent-Setup--<code>.exe"`, `Cache-Control: no-store`.
* The React page fetches it as a blob with the session header and saves it under the server-provided name. The code is **not** in any URL, JSON body, or browser storage, and is dropped from memory after the download starts.

Why a file name: it is the only channel that reaches a double-clicked, unsigned, un-modified installer without user typing and without a per-user build step; the installer can read its own name. Cost: the code is visible in the Downloads folder and browser download list until used/expired. This is acceptable only because the code is single-use, 30-minute, bound to one approved request, and useless after install. Alternatives rejected: typing a code (violates the brief), a companion file or zip (extra user steps, breaks "double-click"), a URL-scheme handler (needs an installed agent), server-side re-signing / patching the exe (no signing infrastructure, fragile with Inno).

## 7. Redemption API

`POST /api/agent/enrollment/redeem` - **no login, no shared key**: possession of a valid code is the credential.

Request: `{ "code": "...", "display_name": "...", "operating_system": "...", "agent_version": "...", "endpoint_id": "<optional uuid4>" }`. Scope/user/org are **ignored if present**.

Processing, in ONE transaction:

1. Per-IP failure rate-limit check (429 + `Retry-After`).
2. Parse code; `h = sha256(secret)`; look up by `token_hash`. Not found -> `401 invalid_code` (identical body for malformed and unknown).
3. Row found (so the caller proved knowledge of the secret), so specific errors are safe: `expired` 410, `already_used` 409, `superseded` 410, `revoked` 403.
4. Re-check the request: exists, owned by `authorization.username`, `organization` equal, status in (`APPROVED`, `ENROLLMENT_PENDING`), approval window not over, requester account still exists; pinned `authorization.scope` equals request `approved_scope` and is a subset of `requested_scope`.
5. **Claim**: conditional UPDATE on the authorization (`redeemed_at IS NULL AND superseded_at IS NULL AND revoked_at IS NULL AND expires_at > now`) - rowcount must be 1, else 409.
6. **Bind request**: conditional UPDATE `status -> ENROLLED, endpoint_id` `WHERE status IN (...) AND endpoint_id IS NULL`; rowcount must be 1 (this is the revoke-race arbiter).
7. Create the endpoint through the existing enrollment internals (no commit inside): unique credential, `credential_hash` only, `monitoring_scope = approved_scope`, `enrolled_request_id`.
8. Audit `enrollment.redeemed`, notify requester ("Agent enrolled"), commit. Any failure before commit rolls everything back, so a half-finished redemption never burns the code.

Response (the **only** time the credential exists in cleartext): `{ endpoint_id, agent_credential, credential_issued_at, monitoring_scope, backend: PUBLIC_BASE_URL }`. No dashboard data, no other users' info.

Failure to deliver (network drop after commit): the code is spent and the endpoint exists with a credential nobody holds. Recovery: an administrator revokes the request and the user submits a new one (or operator `manage_endpoints.py --revoke-credential`). Documented limitation; automatic re-key is deliberately not offered.

## 8. Scope enforcement (P5)

* Server: `ingestion_service` drops events whose `event_category` is outside `endpoint.monitoring_scope` (counted as `out_of_scope`, not stored). NULL scope (existing endpoints) = unchanged behaviour.
* Agent: after redemption sets `CATEGORIES` to the approved scope in its config so it does not even collect the rest.
* Prohibited data (passwords, keystrokes, messages, documents, screenshots, camera/mic) are not collectable categories and can never be in a scope.

## 9. Revocation (P6)

`revoke` (existing admin action) now additionally: supersedes/revokes every unredeemed code (`revoked_at`), clears the endpoint `credential_hash` + marks it `revoked` (existing), and records counts in the audit entry. Redemption's step 6 makes a concurrent redeem lose or win cleanly (if the redeem wins first, revoke then clears the credential it just issued).

## 10. Windows agent and installer

Installer (Inno Setup, existing `ubads_agent.iss`, still admin-elevated by Windows UAC - not bypassed):

1. On finish of file copy (`ssPostInstall`), `[Code]` extracts the code from its own file name (`UBADS-Agent-Setup--<code>.exe`; tolerates Windows' ` (1)` suffix). **No code in the name -> existing behaviour (no enrollment, nothing else changes).**
2. Writes the code to `%LOCALAPPDATA%\UBADS\Agent\enrollment.pending` (user-private profile ACL), runs `ubads-agent.exe --enroll-from-installer` hidden and waits. The code is never on a command line and Inno logging cannot see it.
3. Agent: reads and **immediately deletes** the file, validates the embedded URL (https, or loopback only with an explicit dev flag), redeems, stores the credential with the **existing DPAPI** store and the URL in `agent.env`, writes the scope to `CATEGORIES`, then `--install-task` and `--start`.
4. Skips enrollment if the machine is **already enrolled** (never auto re-enroll); leaves the code unredeemed to expire.
5. Exit codes -> plain-language message boxes: success; invalid/expired/used code (re-download from the portal); revoked; server unreachable; already enrolled. Failure never starts the agent.
6. Upgrade-safe: does not touch existing state/credentials unless a code is present AND the machine is unenrolled.

The agent keeps every existing command (`--setup`, `--collect`, ...) and the shared-key path.

## 11. Rate limits and logging

* Redeem failures: per IP (`ENROLLMENT_REDEEM_MAX_FAILURES_PER_IP` per 15 min, default 10). Mint: per request and per user (default 10/hour).
* Logs contain request id, endpoint id, outcome. Never the code, secret, hash prefix, filename, or credential. Tests assert this with log capture.

## 12. Verification plan (maps to the brief)

Backend tests (isolated in-memory / temp-file DBs): valid redemption; expired; invalid/malformed; reused; concurrent redemption (threads on a file DB: exactly one credential); revoked request; revoke-vs-redeem race; wrong user / wrong organization (tampered rows); scope tampering (body scope ignored, pinned-scope mismatch rejected, out-of-scope events dropped); hash-only storage; log leakage; credential provisioning; DPAPI round-trip; registration/heartbeat/ingest after redemption; existing shared-key endpoint and legacy credentials still work; revoked credential rejected; approval/portal/notification regressions; Playwright download-with-code flow.
Agent tests: code parsing, URL validation, file consumed once, DPAPI storage, exit codes.
Installer test (Stage 4E): a **test build of the same `[Code]` logic** with `PrivilegesRequired=lowest`, its own AppId/directory, isolated `UBADS_STATE_DIR` and `UBADS_TASK_NAME` so the installed agent and its real scheduled task are never touched. Honest limit: I cannot approve a UAC prompt, so the genuinely elevated install path is verified by a manual checklist, not claimed as tested.

## 13. Known limitations

* Code visible in the Downloads file name until used/expired.
* Unsigned installer (SmartScreen/antivirus warnings expected).
* Lost-credential-after-commit requires admin revoke + new request.
* In-memory rate limits reset on restart; single backend process.
* Task runs as the installing user and starts at that user's sign-in (unchanged).
