# Frontend — UBADS Dashboard

**Status:** Professional SOC-style UI foundation with a strict LIVE/DEMO
data-mode architecture. **Still not wired to real event/user/anomaly data**
— the backend only exposes `GET /health` (see `backend/app/main.py`). Every
LIVE-mode page calls its real, prepared endpoint and honestly renders "not
available yet" (404) or "backend unavailable" (network failure) — nothing
is fabricated. `log-collector/` and `ml-service/` were not touched.

## Product identity

**UBADS** — User Behavior Anomaly Detection System — *Behavior Anomaly
Detection*. Dark, cyan-accented, professional SOC/UEBA aesthetic (see
`tailwind.config.js`'s `surface`/`accent`/`status` tokens).

## The two data modes (critical architectural rule)

| | LIVE ENDPOINT DATA | DEMO / SYNTHETIC DATA |
|---|---|---|
| Source | Real backend API calls | `src/demo/` only |
| Written to real DB? | N/A (read-only so far) | **Never** |
| Labeling | `DataModeBanner`, Topbar badge | Every view also shows a `DemoTag` ("DEMO DATA") or "SIMULATED RESULT" |

`src/context/DataModeContext.jsx` is the **single source of truth** for
which mode is active (persisted to `localStorage` for convenience only —
it has no effect on any backend data). Toggle it via the Topbar badge, the
Settings page, or the banner button on Demo Lab. No page independently
decides which data to show — they all read this context.

**Demo data lives only in `src/demo/`** (`demoData.js`,
`scenarios/scenarios.js`) and is never merged with a LIVE API response.
Running a Demo Lab scenario calls a deterministic, hand-authored JS
function — never a real model, never the real database.

## Structure (new/changed since Phase 8A)

```
frontend/src/
├── context/DataModeContext.jsx        # LIVE/DEMO global switch
├── hooks/
│   ├── useApiResource.js               # loading / notAvailable(404) / unreachable / data
│   └── useBackendHealth.js
├── demo/
│   ├── demoData.js                     # ALL fabricated data lives here, nowhere else
│   └── scenarios/scenarios.js           # 5 Demo Lab scenarios + runScenario()
├── api/
│   ├── client.js                       # unchanged — the one place VITE_API_BASE_URL is read
│   └── endpoints.js                     # getHealth (real) + 8 prepared-not-yet-built calls
├── components/
│   ├── layout/{Sidebar,Topbar,Layout}.jsx   # updated: 9 nav items, mode/backend/endpoint badges
│   ├── ui/                              # Card, StatCard, StatusBadge, Badge (+RiskBadge/DemoTag),
│   │                                     # EmptyState (+action), DataTable (+onRowClick),
│   │                                     # ResourceState, DataModeBanner, Drawer, Pagination,
│   │                                     # PrivacyNote
│   └── dashboard/BehavioralActivityChart.jsx
└── pages/
    ├── Overview.jsx            (was Dashboard.jsx)
    ├── LiveMonitoring.jsx        (new)
    ├── Events.jsx                (rewritten: search/filters/pagination/detail drawer)
    ├── UsersBaselines.jsx        (was Users.jsx)
    ├── Anomalies.jsx             (rewritten: summary cards + risk badges)
    ├── DemoLab.jsx                (new — 5 scenario cards)
    ├── Reports.jsx                (rewritten: 5 report sections)
    ├── EndpointEnrollment.jsx    (new)
    └── Settings.jsx               (rewritten: 6 sections)
```

## Backend change made for this phase

`backend/app/main.py` and `backend/app/core/config.py` gained **CORS
middleware** — without it, every browser call from the Vite dev server
(a different origin) to the backend was silently blocked, which is not an
application bug but a missing, necessary piece of API-integration
plumbing. This is the only backend change; no route, log-collector, or
ml-service logic was touched. Verified: all 99 existing Python tests still
pass.

## Prepared (not yet built) backend routes

`src/api/endpoints.js` defines calls for routes the backend doesn't have
yet: `GET /api/events`, `/api/events/:id`, `/api/users`,
`/api/users/baselines`, `/api/anomalies`, `/api/ml/collection-status`,
`/api/reports/data-quality`, `/api/endpoints/status`. Calling any of these
today returns 404, which every page renders as an honest "Not available
yet" state via `ResourceState`/`useApiResource` — never a fabricated
number.

## Install and run

```powershell
cd frontend
npm install
Copy-Item .env.example .env
npm run dev
```

Open the printed URL (typically `http://localhost:5173/`). Start the
backend too (from the project root) so LIVE-mode pages can actually reach
`/health` and Settings' "Test Connection" can succeed:

```powershell
uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

## Run the demo experience

No setup needed — Demo Lab and demo data are fully self-contained:

1. Open the app, click the Topbar's `LIVE DATA` badge (or use Settings →
   Demo Mode) to switch to `DEMO MODE`.
2. Go to **Demo Lab**, click **Run Scenario** on any of the 5 cards
   (Unusual Login Time, Unusual Process Activity, Unusual Activity Burst,
   Unusual Device Activity, Combined Behavioral Deviation).
3. The result is clearly labeled **SIMULATED RESULT** — it is a scripted
   walkthrough, not real model output, and nothing is written to the real
   database.
4. Overview, Events, Users & Baselines, and Anomalies all also switch to
   showing labeled demo data while Demo Mode is active.

## Build for production

```powershell
npm run build
npm run preview
```

## Verification performed for this phase

- `npm run build` succeeds.
- Headless (Playwright) check of all 9 routes in both LIVE and DEMO mode:
  correct heading on every page, zero JS/React exceptions (`pageerror`),
  zero application-level console errors.
- Confirmed the only console noise before the CORS fix was the browser's
  own network-tab logging for calls to not-yet-built routes (expected);
  after the fix, `/health` succeeds end-to-end with the real backend
  running, and Settings' "Test Connection" only ever shows "Connected"
  when that call genuinely succeeds.
- Demo Lab: ran a scenario, confirmed "SIMULATED RESULT" renders.
- Events: clicked a row, confirmed the detail drawer opens with the right
  fields.
- Full Python test suite (`pytest`, 99 tests) re-run after the backend CORS
  change — all still pass.

## What's intentionally NOT implemented in this phase

- No real `/api/*` routes on the backend — only the prepared frontend
  calls and honest "not available yet" states.
- No ML/anomaly-detection model, no Isolation Forest, no real anomaly
  scores.
- No hosted/published Windows agent installer — Endpoint Enrollment's
  download button uses `VITE_AGENT_INSTALLER_URL` if set (production path,
  not implemented yet). Without it, in `npm run dev` only (Phase 14A), the
  button downloads the real local `UBADS-Agent-Setup.exe` from
  `public/downloads/` (see that folder's `README.md` and
  `agent/README.md` "Downloading the local installer from the frontend"),
  clearly labeled as a local development build — never in a production
  build, where `vite.config.js` strips that folder from the output
  entirely. `VITE_AGENT_INSTALLER_URL` itself is never hard-coded to a
  filesystem path.
- No Azure deployment.
- No code-splitting for the `recharts` bundle (flagged by the build as
  >500KB after minification) — acceptable for an academic-scale local
  demo; would be worth addressing before a real production deployment.
