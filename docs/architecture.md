# Architecture

## End-to-end data flow

```
Authorized Windows Computer
        │
        ▼
Windows Endpoint Agent             agent/                 [IMPLEMENTED — Phase 10/11]
        │
        ▼
Windows Event Collector            log-collector/          [IMPLEMENTED — Phase 2-4,
        │                                                    cursor-aware since Phase 11]
        ▼
Normalization                      event_parser.py          [IMPLEMENTED — Phase 2-4,
        │                                                    NULL-SID/service-SID rules Phase 11]
        ▼
Validation                         validation.py            [IMPLEMENTED — Phase 3]
        │
        ▼
Persistent Collection Cursor       agent/checkpoint.py      [IMPLEMENTED — Phase 11]
        │
        ▼
Per-Agent Authentication           agent/credential_store.py, [IMPLEMENTED — Phase 11]
                                    backend/app/security/agent_auth.py
        │
        ▼
Secure Backend API                 backend/ (X-Endpoint-Id +  [IMPLEMENTED — Phase 9/10/11]
                                    X-Agent-Credential)
        │
        ▼
Endpoint Identity                  backend endpoints table   [IMPLEMENTED — Phase 9/11]
                                    (credential_hash, never
                                     the raw secret)
        │
        ▼
Events Database                    data/app.db (SQLite,      [IMPLEMENTED — Phase 3,
                                    endpoint_id column)         endpoint_id since Phase 11]
        │
        ▼
Behavioral Feature Engineering     ml-service/                [IMPLEMENTED — Phase 5]
        │
        ▼
ML Readiness Check                 collection_status.py       [IMPLEMENTED — Phase 6A,
        │                                                        still INSUFFICIENT_REAL_DATA]
        ▼
Future ML Detection                Isolation Forest, etc.     [NOT IMPLEMENTED]
        │
        ▼
Dashboard                          frontend/                  [IMPLEMENTED — Phase 8, shows
                                                                 real data for everything above
                                                                 that exists; honestly reports
                                                                 "not available" for what doesn't]
```

Two collection paths exist and both end up in the same `events` table:
1. **Local, direct**: `log-collector/collector.py` run directly on the
   machine hosting `data/app.db`, writing to SQLite itself (Phase 2-4).
2. **Agent, remote-capable**: `agent/agent.py` (Phase 10/11), which reuses
   the exact same collector/normalizer/validator but sends events to the
   backend over HTTP instead of writing to SQLite directly — the backend
   then does the same validate-and-store step, additionally attributing
   each event to the authenticated endpoint. Today both paths are
   typically exercised on one machine (no remote endpoint is deployed
   yet), but the agent path is what makes a genuinely separate,
   authorized endpoint possible without code changes later.

## Component overview

| Folder | Purpose | Status |
|---|---|---|
| `agent/` | Windows endpoint agent: collects real events via log-collector's collector (persistent per-category cursor since Phase 11), submits them to the backend over HTTP with its own per-agent credential; packageable into a local `.exe` (Phase 13) and a real local installer (Phase 14) | Implemented, verified locally (Phase 10/11); local PyInstaller executable and Inno Setup installer implemented and verified (Phase 13/14) — not signed, not hosted, not a Windows service |
| `log-collector/` | Collects real Windows event/activity logs (auth, file, process, device), normalizes, validates, stores them | Implemented (Phase 2-4); cursor primitives + typed access errors added Phase 11 |
| `backend/` | FastAPI service: reuses log-collector/ml-service to serve real events/users/baselines/ML-readiness/data-quality to the frontend; accepts real agent-submitted events with per-agent authentication; lists enrolled endpoints and filters events per-endpoint (Phase 14) | Implemented (Phases 1, 8C, 9, 10, 11, 14) — `/api/anomalies` 404s pending Phase 6B |
| `ml-service/` | Behavioral feature engineering from real events (Phase 5); scikit-learn anomaly detection (later phase) | Feature engineering implemented; ML model not yet implemented |
| `frontend/` | React + Vite + Tailwind SOC/UEBA-style dashboard, LIVE/DEMO data-mode split | Implemented (Phase 8), connected to the real backend |
| `data/` | `app.db` (SQLite: `events` incl. `endpoint_id`, `behavior_features`, `endpoints` incl. `credential_hash`), `raw/` (optional JSON dumps) | In use — gitignored |
| `models/` | Reserved for future trained ML model artifacts (gitignored) | Not yet used — no model exists |
| `config/` | Shared environment configuration (`config/.env`), used by every Python component including the agent | `.env.example` up to date |
| `tests/` | Automated tests: `backend/`, `log_collector/`, `ml_service/`, `agent/` | 255 tests, all passing at the end of Phase 14 (see root README) |

## Why this shape

Each top-level component is a separately deployable unit. Locally,
everything runs as processes on one machine (backend as a FastAPI/uvicorn
process, log-collector/agent as scripts, ml-service as an importable
library). This mirrors how they can be deployed to Azure later without
restructuring:

- `agent/` → could run on many authorized endpoints, each pointed at the
  same central `backend/` over the network — no code change, only
  `BACKEND_URL` configuration per machine, plus its own automatically
  enrolled per-agent credential (Phase 11) rather than a shared secret.
- `log-collector/` → could become a script run via Windows Task Scheduler
  (still used locally by the agent's collection logic either way), or
  later ship data to Azure Event Hub / Log Analytics.
- `backend/` → could become an Azure App Service / Container App.
- `ml-service/` → could become an Azure ML endpoint or stay embedded in
  the backend, depending on scale.
- `data/` (local) → could become Azure Blob Storage / Azure SQL.
- `models/` (local files) → could become Azure ML Model Registry.

The key design rule enabling this: application code never reads
configuration or environment variables directly — it goes through
`backend/app/core/config.py` (backend) or `agent/config.py` (agent), both
reading the same shared `config/.env`. When a piece moves to Azure, config
values change (e.g. `DATABASE_URL`, `BACKEND_URL`), not application logic.

## Why FastAPI over Flask

FastAPI was chosen for the backend because:

- Built-in request/response validation via Pydantic, which pairs naturally
  with the structured log/event data this project ingests.
- Async support out of the box, useful once the backend is receiving log
  events from multiple machines concurrently.
- Automatic interactive API docs (`/docs`), useful for a research project
  where we'll be manually testing ingestion/query endpoints often.
- Comparable simplicity to Flask for small apps, so there's no real
  downside at this stage.

## Why SQLite locally

SQLite requires no separate server process, stores data in a single file
under `data/` (gitignored — this may hold real, sensitive activity data),
and is accessed through SQLAlchemy. Because SQLAlchemy abstracts the
engine, swapping `DATABASE_URL` to Azure SQL/PostgreSQL later does not
require rewriting queries or models. Both `log-collector/` and `backend/`
(via `app/db/database.py`, used by the new `endpoints` table) point at the
same file through independent SQLAlchemy `Base`s — see `backend/README.md`
"Two databases, one file."

## Why the agent talks over HTTP instead of writing SQLite directly

A remote, authorized endpoint has no access to the central machine's local
SQLite file — HTTP to the backend is the only viable transport once
`agent/` runs somewhere other than the backend's own machine. Reusing
`log-collector`'s collector/normalizer/validator keeps the event shape and
rules identical regardless of which path (local direct write, or agent
over HTTP) produced a given row.
