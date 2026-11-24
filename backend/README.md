# Backend — UBADS API (Phase 1, 6B, 8C, 9, 10, 11, 14)

**Status:** FastAPI app with `GET /health`/`GET /ready` (Phase 1 / Phase 9),
the real API routes the frontend expects (Phase 8C: events, users, user
baselines, ML collection status, data-quality reports, endpoint status),
a production-readiness foundation (Phase 9: environment-aware config/CORS,
structured logging, safe error handling), **real, authenticated event
ingestion** from the Windows endpoint agent (Phase 10 —
`POST /api/ingest/events`), **per-agent credentials with endpoint
impersonation protection** (Phase 11), and **multi-endpoint filtering for
the dashboard** (Phase 14 — `GET /api/endpoints`, `endpoint_id` on every
event — see [`agent/README.md`](../agent/README.md)), and an
endpoint/user-scoped Isolation Forest research prototype (Phase 6B) with
admin-only training/status/results APIs and post-ingestion inference. It
has not been validated using a labeled evaluation dataset; no accuracy
claims are made.
**No Windows service exists yet** — a local installer/executable exists
(Phase 14, unsigned, unpublished — see agent/README.md), but the agent it
installs still runs as a foreground process, manually started.

## Project structure

```
backend/app/
├── main.py                  app + CORS + lifespan (startup/shutdown logging)
├── api/                     HTTP surface only (params, status codes, no business logic)
│   ├── system.py             GET /health, GET /ready
│   ├── events.py, users.py, anomalies.py, ml.py, reports.py, endpoint_status.py
│   ├── endpoint_identity.py  POST /api/endpoints/register, /heartbeat (Phase 9, per-agent auth Phase 11)
│   └── ingest.py              POST /api/ingest/events (Phase 10, per-agent auth Phase 11)
├── services/                composes reused functions and anomaly pipeline
│   ├── events_service.py, users_service.py, baselines_service.py,
│   │   ml_reports_service.py, endpoint_status_service.py
│   ├── anomaly_service.py   endpoint-scoped model training, inference and persistence
│   ├── endpoint_identity_service.py   (Phase 9; enrollment/credential issuance Phase 11)
│   └── ingestion_service.py            (Phase 10 — reuses validation.validate_event
│                                         + storage.insert_event; endpoint_id attribution
│                                         added Phase 11; no new validation rules)
├── repositories/
│   └── pipeline_bridge.py    imports log-collector's `storage` and ml-service's
│                              `collection_status`, `data_quality`,
│                              `user_classification_diagnostics`, `baseline_stats`,
│                              `user_identity` directly (see below)
├── models/
│   ├── endpoint.py            backend-native endpoint identity and credentials
│   └── anomaly.py             Phase 6B — anomaly records in the event database
├── schemas/                  Pydantic request/response models
├── security/
│   └── agent_auth.py          Phase 9 shared-secret check, narrowed in Phase 11 to an
│                                ENROLLMENT-only key + per-agent credential verification
└── core/
    ├── config.py               environment-aware settings (dev vs. production)
    ├── logging_config.py        NEW (Phase 9) — structured logging setup
    ├── errors.py                 NEW (Phase 9) — safe unhandled-exception handler
    └── db/database.py            backend's OWN SQLAlchemy Base/engine (Phase 1,
                                    idle until Phase 9's `endpoints` table)

backend/manage_endpoints.py    NEW (Phase 11) — local operator CLI: list endpoints,
                                 revoke a stuck/compromised endpoint's credential
                                 (talks directly to the DB, never over HTTP)
```

## Architecture — reuse, don't duplicate

Every data-serving route reads from the exact same real data
`log-collector/` and `ml-service/` already produce — nothing here
re-implements event storage, account classification, or readiness rules.
`log-collector/` and `ml-service/` are hyphenated directory names (not
valid Python packages) — `pipeline_bridge.py` adds them to `sys.path` and
imports their modules directly, the same pattern
`ml-service/feature_engineering.py` already used internally. This means:
account classification rules live only in
`log-collector/event_parser.py`; ML-readiness criteria live only in
`ml-service/collection_status.py`; data-quality logic lives only in
`ml-service/data_quality.py`. `anomaly_service.py` calls the feature and
Isolation Forest functions in `ml-service/anomaly_detection.py`, grouping
by authenticated endpoint and resolved Windows user.

`storage.py` now also supports endpoint-filtered event reads for anomaly
inference; the existing ingestion and descriptive baseline paths are
unchanged.

**Two metadata bases, one database URL.** `log-collector/storage.py` owns `events`,
`behavior_features` and `anomaly_detections` on its own SQLAlchemy `Base`.
`endpoints`, dashboard accounts/sessions, enrollment, and audit records
live on the backend's separate SQLAlchemy `Base`. Alembic loads both bases
and migrates them together. Both engines consume the same `DATABASE_URL`;
relative SQLite paths resolve against the project root. SQLite remains the
development default; PostgreSQL URLs use the `postgresql+psycopg://` driver.

## Database setup and migrations

Schema changes are **not** run by API startup, `init_db()`, or the user /
endpoint management CLIs. From the project root, configure the same
`DATABASE_URL` for the backend and event storage, then run:

```powershell
python -m alembic upgrade head
uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --no-access-log
```

The versioned history is in [`migrations/`](migrations/). Revision
`fe1c1f566143` creates/adopts the full schema across both metadata bases
and carries forward additive columns and data backfills from the former
startup mutations. Revision `905c0c7672fc` converts the seven fractional
`behavior_features` columns from integer to floating-point. SQLite
migrations rebuild only the affected table through Alembic batch
operations; PostgreSQL uses `ALTER COLUMN TYPE`. These migrations retain
rows and do not drop tables. Back up and rehearse migrations on a
disposable copy before running them against any valuable database.

For PostgreSQL, install the pinned backend requirements and configure
`DATABASE_URL=postgresql+psycopg://USERNAME@HOST:5432/DATABASE?sslmode=require`.
For the RVCE Azure server, the safe shape is
`postgresql+psycopg://USERNAME@ubads-postgres-rvce.postgres.database.azure.com:5432/ubads?sslmode=require`;
provide the password only through the hosting platform's secret configuration.
Production rejects PostgreSQL URLs that do not explicitly require TLS. The
SQLAlchemy engines use `pool_pre_ping`, bounded connection and pool timeouts,
a recycle interval, and a small bounded pool; tune these with the
`DATABASE_POOL_*` and `DATABASE_CONNECT_TIMEOUT_SECONDS` settings rather than
embedding deployment-specific values in code. A PostgreSQL migration test runs
only when `UBADS_TEST_POSTGRES_URL` is explicitly supplied; it requires a
database name ending in `_test` or `testing` and creates/drops only a unique
temporary schema in that test database. SQLite tests use temporary files or
in-memory databases.

The reported Azure server details are deployment inputs, not repository
credentials. Before starting the backend, confirm that the hosting environment
can resolve and reach the Azure PostgreSQL hostname, that its network access is
allowed by the server configuration, and that the configured identity has
access to database `ubads`. A successful VS Code PostgreSQL extension
connection does not prove App Service or another hosting environment can
connect.

## Endpoints

| Route | Method | Behavior |
|---|---|---|
| `/health` | GET | Process liveness only — never checks a dependency (see `/ready`). |
| `/ready` | GET | Runs `SELECT 1` through both the identity/auth database engine and event-storage engine; returns 200 `{"status":"ready"}` or 503 `{"status":"not_ready"}`. Does not report ML readiness. |
| `/api/events` | GET | Real stored events, filterable by `category`/`username`/`event_id`/`start_time`/`end_time`/**`endpoint_id`** (Phase 14), paginated via `limit`/`offset`. Excludes `raw_event_data`, `user_sid`, `access_list_raw`. Every row now includes `endpoint_id` (NULL for pre-Phase-11/local-collector rows) — see "Multi-endpoint dashboard support" below. |
| `/api/events/{id}` | GET | One event by database primary key. 404 if not found. |
| `/api/endpoints` | GET | **Admin-only (Phase 14).** Every enrolled endpoint's safe identity fields (never a credential/hash), used by the dashboard's per-endpoint filter. |
| `/api/users` | GET | Human-candidate accounts only (reuses Phase 6A.1's `classify_account`/`generate_user_classification_report` exactly). |
| `/api/users/baselines` | GET | Per-user behavioral summary built from real `behavior_features` rows + `collection_status`/`baseline_stats`. `baselineStatus` is `insufficient_data` / `building` / `ready`; never invented. |
| `/api/ml/collection-status` | GET | The exact dict `python feature_engineering.py --collection-status` produces, plus `human_candidate_account_count`. |
| `/api/reports/data-quality` | GET | The exact dict `python feature_engineering.py --data-quality-report` produces. |
| `/api/endpoints/status` | GET | `online`/`collectorRunning`/`lastHeartbeat` are always `null` — there is no persistent agent/heartbeat mechanism feeding this route, so these are genuinely unverifiable, not fabricated as "running". `lastEvent`/`currentUser`/`categories` are real, derived from stored events. Unchanged since Phase 8C. |
| `/api/anomalies` | GET | **Admin-only.** Recorded detections, endpoint/time filters, severity totals and pagination. |
| `/api/anomalies/{id}` | GET | **Admin-only.** One detection with model version and heuristic feature explanation. |
| `/api/ml/anomaly-status` | GET | **Admin-only.** Per-profile training sufficiency, model version, data source and stale status. |
| `/api/ml/train-anomaly-models` | POST | **Admin-only.** Trains from real, completed endpoint/user windows; requires at least 20 windows per profile. |
| `/api/endpoints/register` | POST | **Phase 9, per-agent auth in Phase 11.** Two modes: (1) presenting only `X-Agent-Api-Key` (the shared **enrollment** key) enrolls a new (or legacy, not-yet-credentialed) endpoint and returns a freshly issued `agent_credential` **once** — refuses (409) if that `endpoint_id` already has a credential; (2) presenting `X-Endpoint-Id` + `X-Agent-Credential` authenticates as that endpoint and only refreshes its display metadata (never re-issues a credential). A body `endpoint_id` that doesn't match the authenticated endpoint is rejected (403). 503 if no enrollment key is configured and no credential was presented. |
| `/api/endpoints/heartbeat` | POST | **Per-agent auth (Phase 11).** Requires `X-Endpoint-Id` + `X-Agent-Credential` — the shared enrollment key is **not** accepted here. Updates `last_seen`/`status` for the authenticated endpoint only; a body `endpoint_id` naming a different endpoint is rejected (403), not silently corrected. Unknown endpoint or wrong credential both return the same 401 (no endpoint-ID enumeration). |
| `/api/ingest/events` | POST | **Phase 10, per-agent auth in Phase 11.** Requires `X-Endpoint-Id` + `X-Agent-Credential` (the shared enrollment key is **not** accepted). Body: `{"log_name": "Security", "events": [<normalized event>, ...]}` — the exact shape `event_parser.normalize_event()` already produces. Each event is validated with log-collector's `validate_event()`; invalid ones are counted and **never stored**; valid ones go through `storage.insert_event()`, attributed to the **authenticated** endpoint (never a body/event-level `endpoint_id`), with dedup-by-`event_uid` now namespaced per endpoint. Returns `{"endpoint_id", "accepted", "duplicates", "validation_errors", "errors"}`. |

## Development vs. production configuration

One `Settings` object (`app/core/config.py`), driven entirely by
`ENVIRONMENT` (`local` default, or `production`) — not two separate config
files:

| Setting | Local (verified) | Production (config-validated, not yet deployed) |
|---|---|---|
| `CORS_ALLOWED_ORIGINS` | Vite dev origins, wildcard-friendly | Must be one or more exact HTTPS frontend origins |
| `DATABASE_URL` | SQLite file at project-root-relative `data/app.db` | Must be a PostgreSQL URL; one shared setting configures both metadata bases, and migrations run separately before startup |
| `MODEL_STORAGE_PROVIDER` | `local` | Must be `azure_blob`; production cannot fall back to local model artifacts |
| `INSTALLER_STORAGE_PROVIDER` | `local` | Must be `azure_blob`; production serves only a private pre-existing Blob artifact |
| `AZURE_INSTALLER_CONTAINER`, `AZURE_INSTALLER_BLOB_NAME` | `ubads-installers`, `releases/UBADS-Agent-Setup.exe` | Private installer artifact location; no public Blob URL or SAS is issued |
| `PUBLIC_BASE_URL` | Optional local fallback | Must be the HTTPS API origin, with no path, query, or credentials |
| `TRUSTED_PROXIES` | Empty; forwarded headers ignored | Optional explicit IP/CIDR ranges only; never use `*` |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | Unset | Optional; enables Microsoft OpenTelemetry export |
| `AGENT_API_KEY` | Unset (new-endpoint enrollment closed; already-enrolled endpoints keep working with their own credential) | Must be set to enable enrollment of new endpoints |
| `LOG_LEVEL` | `INFO` | Same knob, set as appropriate |

Production configuration is validated when `Settings` loads. Besides the
PostgreSQL, Azure Blob, HTTPS API origin, and exact CORS requirements above,
Azure account URL/container configuration is validated without attempting
cloud connectivity. Installer Blob settings are also required in production.
Both SQLAlchemy engines consume `DATABASE_URL`; they
cannot be independently pointed at different production databases.

## Persistent anomaly model artifacts

The backend uses `MODEL_STORAGE_PROVIDER=local` by default and stores
versioned model artifacts under `ANOMALY_MODEL_DIR` (default
`models/anomaly-detection/`). To use Azure Blob Storage, set
`MODEL_STORAGE_PROVIDER=azure_blob`, `AZURE_STORAGE_ACCOUNT_URL` to the
HTTPS storage-account URL, and `AZURE_STORAGE_CONTAINER` to a **pre-existing**
private container. The Azure implementation uses `DefaultAzureCredential`;
grant only the backend's managed identity (or other authorized backend
identity) the required blob read, write, and list permissions. It never
creates containers or Azure resources.

Installer release artifacts use the same storage account but a separate
private container by default. Set `INSTALLER_STORAGE_PROVIDER=azure_blob`,
`AZURE_INSTALLER_CONTAINER`, and `AZURE_INSTALLER_BLOB_NAME`; the backend
uses `DefaultAzureCredential` and the App Service managed identity. Grant
that identity **Storage Blob Data Reader** scoped to the installer container.
No anonymous/public access or SAS URL is used. Publish a reviewed release
artifact to the pre-existing container; production rejects local installer
storage and never serves the development `agent/dist` file as a fallback.

The Azure SDK dependencies are pinned in `backend/requirements.txt`.
`scikit-learn==1.6.1` and `joblib==1.6.0` are pinned together; model metadata
records both library versions, and incompatible artifacts are rejected before
deserialization. Each model version has a JSON metadata manifest and SHA-256
digest. The digest is checked before Joblib loading. Since Joblib files are
Python-serialized objects, local artifact directories and the Azure container
must remain writable only by trusted backend identities. Existing unversioned
local artifacts without integrity manifests are ignored and require retraining.
Model storage outages or invalid artifacts cause status/inference to fail
safely; they do not undo successfully stored events.

## Azure App Service and Static Web Apps preparation

Phase 3 prepares but does not deploy UBADS. For Linux App Service, deploy
tracked application sources including sibling `log-collector/` and
`ml-service/` modules, use the root `requirements.txt`, and set the startup
command to `bash startup.sh`. Exclude `.env` files, `data/`, `agent/.state/`,
model artifacts, virtual environments, `node_modules`, and local build
outputs; do not deploy a working-directory ZIP. The script binds to
`0.0.0.0` and uses
`PORT`/`API_PORT`; it never runs Alembic or creates/changes schema. Run
`python -m alembic upgrade head` as a separate, controlled release step,
after testing and backup.

Production `Settings` require a PostgreSQL `DATABASE_URL`, Azure Blob model
and installer providers, a valid HTTPS `PUBLIC_BASE_URL`, and exact HTTPS
`CORS_ALLOWED_ORIGINS`. Backend auth/identity and event storage share the
same URL. SQLite and local storage remain the local-development defaults.
Blob configuration requires an HTTPS account URL and pre-existing private
containers; the App Service managed identity needs scoped blob data access.

Use the App Service system-assigned managed identity for Key Vault
references (`Key Vault Secrets User`) and Blob access. Supply credentials
such as `DATABASE_URL` and, when enrollment is enabled, `AGENT_API_KEY`
through Key Vault references in App Service settings, never a deployed
`.env` file. `APPLICATIONINSIGHTS_CONNECTION_STRING` is optional; when set,
the app initializes the pinned Microsoft OpenTelemetry distro. Automatic
FastAPI and Azure SDK instrumentation is disabled; request logs use route
templates and omit query strings, concrete path parameters, headers, and
bodies. No real telemetry export was verified.

For Static Web Apps, set the app location to `frontend`, output to `dist`,
and build with `npm run build`; set `VITE_API_BASE_URL` to the HTTPS API
origin. The Vite build rejects missing or non-HTTPS production API URLs.
`frontend/public/staticwebapp.config.json` supplies BrowserRouter fallback.
Configure backend CORS with the exact deployed frontend origin. Installer
packages are streamed only through the authenticated API after owner and
approval checks. The installer Blob remains private; no anonymous access or
SAS is configured. The currently checked-in installer is unsigned and has
not been tested from Azure or on another Windows computer. Windows agents
must use the HTTPS API URL and keep normal certificate verification enabled.

Configure platform health monitoring on `/ready`, which checks both
database engines; `/health` is process liveness only. Before production,
define event-retention requirements, enable PostgreSQL backup/PITR, rehearse
restore to a disposable database, and keep model artifacts private with a
retention policy compatible with rollback. Deploy immutable builds and
rollback only to code compatible with the applied schema. Azure resources,
PostgreSQL connectivity, managed identity, Key Vault, Blob operations,
Static Web Apps, and Application Insights have not been deployed or tested
against real cloud services.

## Security foundation (Phase 9, per-agent credentials in Phase 11)

```
Enrollment (once per endpoint):
    Agent --X-Agent-Api-Key: <shared ENROLLMENT key>--> POST /api/endpoints/register
    Backend creates the endpoint, generates a random 256-bit credential,
    stores ONLY its SHA-256 verifier, returns the credential ONCE.

Every later call (heartbeat, re-registration, ingestion):
    Agent --X-Endpoint-Id, X-Agent-Credential--> backend
    require_authenticated_endpoint() verifies the pair and returns the
    endpoint record. Routes act ONLY on that authenticated endpoint.
```

- **Endpoint A → credential A, Endpoint B → credential B.** Not a single
  shared secret for every agent (Phase 9/10's model). Knowing endpoint B's
  ID is useless without B's credential, and changing `ENDPOINT_ID` on
  agent A's config does not let it act as B — enforced server-side by
  `reject_mismatched_endpoint_id()` on every route that accepts an
  optional body `endpoint_id` (register, heartbeat, ingest); see the
  impersonation tests in `tests/backend/test_endpoint_identity_api.py`
  and `test_ingest_api.py`.
- **Secure by default**: with `AGENT_API_KEY` (the enrollment key) unset,
  no *new* endpoint can enroll (503) — already-enrolled endpoints are
  unaffected, since they never use that key again.
- **The enrollment key can never overwrite or re-key an already-enrolled
  endpoint** (409) — the only way to replace a lost/compromised
  credential is the explicit local operator action
  `backend/manage_endpoints.py --revoke-credential <id>`.
- **SHA-256, not bcrypt/PBKDF2, for the credential verifier** — a
  deliberate choice, not an oversight: those slow hashes exist to protect
  low-entropy human passwords from offline guessing. The credential is 32
  bytes (256 bits) from `secrets.token_urlsafe`, which no amount of hash
  speed makes guessable — the same approach most platforms use for API
  tokens. Comparison uses `hmac.compare_digest` (constant-time).
- **Never logs a key or credential value** — only that a request was
  accepted or rejected and why.
- **Ingestion (Phase 10, endpoint-attributed since Phase 11)** validates
  server-side (even though the agent also validates before sending —
  defense in depth) and stores only through the existing
  `storage.insert_event()`, now passed the *authenticated* endpoint's ID.
  There is no unauthenticated ingestion path, and a per-event
  `"endpoint_id"` key inside a submitted event dict is ignored — only the
  authenticated identity is ever stored.
- **Development-grade foundation, not production secret management**: no
  credential rotation schedule, no HSM/KMS, no rate limiting. Documented
  as a known limitation, not silently implied to be production-ready.

## Error handling

- Deliberate `HTTPException`s (404/401/503 from services) pass through
  with their intentional, safe `detail` message unchanged.
- Any genuinely unexpected exception is caught by a global handler
  (`app/core/errors.py`): the client always gets a generic
  `500 {"detail": "Internal server error."}`; the real exception and
  traceback are logged server-side only, never returned to the client.

## Logging

Structured via `app/core/logging_config.py`, level controlled by
`LOG_LEVEL`. Logs startup/shutdown, the CORS origins in effect, whether
`AGENT_API_KEY` is configured, agent-auth rejections (never the key
value), and any unhandled exception or service-level 503. Never logs passwords, tokens, key values, or raw event payloads. HTTP
request summaries contain only method, route template, status, and elapsed
time; they omit concrete path parameters, query strings, headers, and body.
The App Service startup disables Uvicorn's raw access logger.
When `APPLICATIONINSIGHTS_CONNECTION_STRING` is set, the Microsoft
OpenTelemetry distro exports the application logs. Automatic FastAPI and
Azure SDK instrumentation is disabled to avoid collecting sensitive request
paths or model-blob identifiers. No cloud telemetry connection has been
tested.

## Known limitation: two classification sources

`GET /api/users` re-derives `account_type` fresh from each event's
username/SID (via `user_classification_diagnostics`), while
`GET /api/users/baselines` (via `collection_status`'s `user_coverage`)
trusts the `account_type` column already stored on each event at
collection time. In practice these agree, since `log-collector/collector.py`
sets that column using the same `classify_account()` function — but if a
row was stored before a classification fix (as happened once in Phase
6A.1), the two endpoints could briefly disagree until it's re-collected.
Documented here rather than silently papered over; not fixed, since it
would mean changing `ml-service/collection_status.py`'s existing logic,
which this project has been explicitly told not to alter.

## Multi-endpoint dashboard support (Phase 14)

`GET /api/events` accepts an `endpoint_id` filter, and every returned row
now carries its own `endpoint_id`. This is the authoritative way to tell
two enrolled endpoints' events apart — never the self-reported
`computer_name` field, which an agent controls and which two different
enrolled endpoints could in principle share. `GET /api/endpoints` (new)
lists every enrolled endpoint's safe identity fields so the frontend can
build a filter from real, credentialed identities rather than deriving
one from event data.

**Verified for real** (not just unit-tested): a second endpoint was
enrolled against the real running backend with its own generated
credential, sent one real ingested event, and `GET
/api/events?endpoint_id=<id>` was confirmed to return exactly that
endpoint's event and nothing from the original endpoint (and vice versa).
The test enrollment and its event were removed afterward — this project's
real database only ever holds real or already-disclosed test data, never
silently left-over fixtures.

## Run

```powershell
python -m alembic upgrade head
uvicorn app.main:app --app-dir backend --reload --host 127.0.0.1 --port 8000 --no-access-log
```

Interactive docs: http://127.0.0.1:8000/docs — health:
http://127.0.0.1:8000/health — readiness: http://127.0.0.1:8000/ready

## Tests

```powershell
pytest tests/backend
```

API tests use private in-memory SQLite databases via dependency overrides.
Migration tests use disposable temporary SQLite databases. The optional
PostgreSQL test uses only an explicitly configured disposable test schema;
it is skipped if `UBADS_TEST_POSTGRES_URL` is unset.

## PLANNED for future phases (not implemented here)

- Credential rotation policy/schedule, rate limiting, HSM/KMS-backed
  secret storage (Phase 11's per-agent credentials are a development-grade
  foundation, not production secret management).
- Real HTTPS with a valid certificate: `requests` (the agent's HTTP
  client) supports HTTPS with normal certificate validation out of the
  box — no agent code change is needed — but no TLS-terminated backend
  deployment exists to actually verify against yet. Local development
  remains plain HTTP.
- Ingestion from agents on genuinely separate physical/virtual machines
  has not been exercised — multiple *distinct enrolled endpoints* have
  been verified for real (Phase 14, including via the packaged agent
  executable), but every one of them, and this backend, ran on the same
  development machine.
- A Windows agent Program-Files installer exists locally (Phase 14 —
  `UBADS-Agent-Setup.exe`, unsigned, unpublished) but no Windows *service*
  wrapper, and no hosted/signed release.
- A richer multi-computer/fleet management UI beyond the Events page's
  per-endpoint filter (Phase 14) — e.g. a dedicated endpoints list page.
- PostgreSQL production operation still requires successful staging
  migration and integration tests against the selected service.
- Anomaly-detection model integration for `GET /api/anomalies`.
- Azure deployment and cloud connectivity (Phase 3 configuration, startup,
  and frontend preparation are implemented; deployment remains unverified).

## Phase 16 — Dashboard authentication and endpoint status

**Dashboard login (operators).** Every dashboard read API (`/api/events`,
`/api/endpoints`, `/api/endpoints/status`, `/api/users*`, `/api/anomalies`,
`/api/ml/*`, `/api/reports/*`) requires `Authorization: Bearer <token>`.
Only `/health`, `/ready`, `/api/auth/login` and the agent routes
(`register`, `heartbeat`, `ingest`, which use per-agent credentials) are open
to unauthenticated callers. Dashboard tokens cannot act as an agent, and
agent credentials cannot read the dashboard.

- Create / reset a login (prompts for the password; min 12 characters; never
  stored in config or the frontend):
  `python backend/manage_dashboard_users.py --create-user NAME`
  (`--list`, `--delete-user NAME` also available).
- Passwords: scrypt with per-user salt. Session tokens: 256-bit random, only
  their SHA-256 is stored, expire after `DASHBOARD_SESSION_HOURS` (default 8),
  revoked on logout. 5 failed logins per username lock it out for 15 minutes
  (`DASHBOARD_LOGIN_MAX_FAILURES`, `DASHBOARD_LOGIN_LOCKOUT_SECONDS`).
- The frontend keeps the token in `sessionStorage` only (cleared when the tab
  closes).

**Do not expose this backend beyond a trusted network without HTTPS.** Login
passwords and tokens travel in request headers/bodies; terminate TLS in front
of the backend (reverse proxy such as Caddy/nginx, or a cloud load balancer),
set `ENVIRONMENT=production` and `CORS_ALLOWED_ORIGINS` to the real dashboard
origin, and set `VITE_API_BASE_URL` to the `https://` backend address when
building the frontend.

**Endpoint connection status.** `GET /api/endpoints` includes
`connection_status`: `online` (heard from within `AGENT_ONLINE_WITHIN_SECONDS`,
default 120s), `stale` (within `AGENT_STALE_AFTER_SECONDS`, default 300s),
`offline`, or `not_enrolled`. The agent sends a heartbeat every cycle.
`GET /api/events?endpoint_id=...` returns only that endpoint's events.

## Phase 17 stage 2 - admin request management and login hardening

**Admin routes** (all require an `admin` session; normal users get 403):
`GET /api/admin/endpoint-requests` (filters: `status`, `q`, `organization`, `limit`, `offset`),
`GET /api/admin/endpoint-requests/{id}` (includes audit history),
`POST .../{id}/approve` (optional narrower `approved_scope`, `note`),
`POST .../{id}/reject` (`reason` required), `POST .../{id}/revoke`,
`GET /api/admin/audit`, `POST /api/admin/auth/unlock`.
Decisions are atomic (two admins racing: one wins, the other gets 409), audited,
and notify the requester. Revoking an INSTALLED request clears the endpoint's
agent credential, so its uploads and heartbeats are rejected (401) immediately.
An admin cannot approve/reject their own request (`ALLOW_SELF_APPROVAL=false`).
Approvals expire after `APPROVAL_VALID_DAYS` (default 7) and become EXPIRED.
No enrollment token is issued in this stage.

**Login throttling** (sliding windows, `DASHBOARD_LOGIN_LOCKOUT_SECONDS`, default 15 min;
nothing is ever locked permanently):
- per username + client IP: `DASHBOARD_LOGIN_MAX_FAILURES` (5) - an attacker only
  locks themselves out, not the real admin on another address;
- per client IP, any username: `DASHBOARD_LOGIN_MAX_FAILURES_PER_IP` (20) - stops
  username spraying;
- per username across all IPs: `DASHBOARD_LOGIN_MAX_FAILURES_PER_USER` (30) - does
  not apply to an IP that signed in successfully within `DASHBOARD_KNOWN_IP_DAYS`.
Unknown and known usernames are throttled and answered identically. Registration
conflicts (username or email taken) return one generic message; fully hiding
account existence would require email verification.

**Other limits:** `REGISTRATION_MAX_PER_HOUR` (20 per IP, every attempt counts),
`REQUEST_CREATE_MAX_PER_HOUR` (10 per user), `MAX_OPEN_REQUESTS_PER_USER` (5).
All counters are IN MEMORY: they reset when the backend restarts and are not
shared between worker processes (fine for the single-process deployment; use a
shared store if you ever scale out). For local development the defaults are
generous enough not to interfere; raise them via the environment if needed.

**Client IP behind a reverse proxy.** By default the direct connection address
is used and `X-Forwarded-For` is ignored (a client can forge it). Set
`TRUSTED_PROXIES` to your proxy's IP/CIDR (e.g. `TRUSTED_PROXIES=127.0.0.1,10.0.0.0/8`)
and the right-most non-trusted `X-Forwarded-For` entry is used. If you run behind
a proxy and do not set this, every client appears as the proxy's address and
shares one budget.

**Recovery if the only admin is throttled:** wait for the window to expire
(<= 15 min), or another admin calls `POST /api/admin/auth/unlock`, or the operator
restarts the backend, or - with access to the server - runs
`python backend/manage_dashboard_users.py --create-user NAME` to reset the
password (also signs out that account's sessions). There is deliberately no
emailed/self-service password reset, so there is nothing to take over remotely.

## Stage 4G - security fixes

* **Scope enforcement uses the Windows event ID.** The category of an uploaded event is derived server-side from
  `event_id` (`event_parser.EVENT_CATEGORY_MAP`); an agent-supplied `event_category` is only accepted if it equals
  that category (or is the `download_related` refinement of a file event). A mismatched label is rejected as
  `event_category_mismatch`; unknown ids as `unsupported_event_id` (both appear in the ingest response `errors`).
  Applies to legacy (unscoped) endpoints too for the id/label consistency and unsupported-id rules.
* **Revocation is final on the shared-key path.** `POST /api/endpoints/register` with the enrollment key refuses (403)
  any endpoint that is revoked or belongs to an approved request, and audits the attempt
  (`enrollment.legacy_reenroll_blocked`). `manage_endpoints.py --revoke-credential` now marks the endpoint revoked
  (final); `--reinstate ENDPOINT_ID` is the explicit operator recovery for non-portal endpoints only.
* **`LEGACY_ENROLLMENT_ENABLED`** switches shared-key enrollment off. Default: on outside production, **off when
  `ENVIRONMENT=production`**. Enrolled agents are unaffected (metadata refresh, heartbeat and ingestion are separate,
  credentialed requests); portal enrollment is unaffected.
