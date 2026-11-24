# ML Service — Feature Engineering, Readiness, and Anomaly Detection

**Status:** Feature engineering and ML-readiness reporting are implemented.
Phase 6B adds endpoint/user-scoped Isolation Forest training and inference.
The model is a research prototype: it has not been validated using a
suitable labeled evaluation dataset, and no accuracy metrics are claimed.
Each profile needs at least 20 completed daily windows before training.

## Pipeline

```
REAL EVENTS (log-collector/storage.py, table "events")
     ↓  group by user_id + time window          (feature_engineering.py)
TIME WINDOW
     ↓  compute per-category feature functions   (features.py)
USER BEHAVIOR AGGREGATION
     ↓
BEHAVIORAL FEATURES
     ↓  save_feature_record (upsert)             (log-collector/storage.py)
FEATURE DATASET (SQLite, table "behavior_features")
     ↓
READY FOR MACHINE LEARNING IN PHASE 6
```

The anomaly path reuses normalized event records, UTC `windowing.py`
boundaries, `user_identity.py`, and `feature_engineering.compute_feature_record`.
Unlike the existing descriptive `behavior_features` baseline table, model
profiles are grouped by both authenticated `endpoint_id` and resolved
Windows user ID so identical users on different endpoints are not combined.
Known system, service, computer and unresolved accounts are excluded.
Existing baseline rows and event-ingestion semantics are unchanged.

## Isolation Forest

- Admin training reads existing endpoint-attributed normalized events and
  trains one deterministic Isolation Forest per eligible endpoint/user
  profile. It does not train from one event or from the `behavior_features`
  table, and profiles below the 20-window threshold remain insufficient.
- Features aggregate activity counts, category breadth, active hours and
  off-hours, authentication outcomes, file activity, process activity,
  device activity and download-related activity where those categories
  exist for that profile. Missing values within an observed category are
  represented as zero. A newly observed category changes the feature set
  and requires retraining before scoring that profile.
- Anomaly score is a relative 0-to-1 composite of the Isolation Forest
  decision score and the maximum robust deviation from the profile's
  training medians (weights 80% / 20%, deviation scale 10); the detection
  threshold is 0.90. Severity is Low from 0.90, Medium from 0.93, and High
  from 0.97. This makes unusual magnitudes distinguishable when
  Isolation Forest trees place all values above a training maximum in the
  same leaf. It is not a probability. Severity is a separate risk
  classification. A detection is not proof of an incident.
- Explanations identify up to three robust median deviations from the
  training profile. These are heuristic observations, not causal feature
  attribution.
- Inference runs after authenticated event ingestion and does not roll back
  accepted events if scoring fails; failures are logged. Only anomalous
  windows are persisted. Models older than 30 days are stale and are not
  used for inference.
- Model artifacts are stored through `model_storage.py`. Local storage is
  the development default under `models/anomaly-detection/` (override with
  `ANOMALY_MODEL_DIR`); Azure Blob Storage is selectable by the backend with
  `MODEL_STORAGE_PROVIDER=azure_blob`. Both providers keep immutable versions,
  metadata manifests, and SHA-256 digests, and validate the digest before
  Joblib deserialization. Only artifacts marked as UBADS-created and matching
  the current artifact, scikit-learn, and Joblib versions are loaded.
- Joblib artifacts are Python-serialized models and must never be loaded from
  an untrusted or shared-writable location. Keep the local directory
  operator-only, or use a private Azure container with access restricted to
  the authorized backend identity. Azure uses `DefaultAzureCredential` and
  requires `AZURE_STORAGE_ACCOUNT_URL` and `AZURE_STORAGE_CONTAINER`; the
  container must already exist. The app does not create Azure resources.
  Model manifests contain profile/training metadata, so keep the container
  private and do not expose raw manifests to users. Artifacts are gitignored
  and separate from event state.
- Saved models record the Python major/minor, exact scikit-learn, and exact
  Joblib versions. The current tested runtime is Python 3.12.6 with
  `scikit-learn==1.6.1` and `joblib==1.6.0`; those versions should be kept
  consistent when training and inference environments are upgraded.
  Incompatible or legacy unversioned files are not deserialized; affected
  profiles need retraining.
- The reproducible synthetic demo uses a temporary directory and synthetic
  normalized events; it does not write to event storage or the model
  directory. Demo Lab scenarios remain illustrative, separate frontend
  content.

```powershell
cd ml-service
..\.venv\Scripts\python.exe demo_anomaly_detection.py
```

Admin API routes: `GET /api/ml/anomaly-status`,
`POST /api/ml/train-anomaly-models`, `GET /api/anomalies` (supports
`endpoint_id`, `start_time`, `end_time`, `limit`, and `offset`), and
`GET /api/anomalies/{id}`.

## Why this integrates here, and reuses Phase 1-4 as-is

- **Events are read via `log-collector/storage.py`'s existing
  `get_all_events()` + `event_record_to_dict()`** — the exact normalized
  shape Phase 3/4 already established, not reinvented. `log-collector/` and
  `ml-service/` are both hyphenated directory names (not valid Python
  packages), so `feature_engineering.py` adds `log-collector/` to
  `sys.path` explicitly and imports `storage` directly — the same approach
  `collector.py` already uses for its own imports.
- **The new `behavior_features` table lives in the SAME `data/app.db`**,
  defined in `log-collector/storage.py` right alongside `events` — per
  Phase 4's stated design principle, this project uses one SQLite database
  for everything rather than a second, unrelated one.
- **Timestamps use the UTC convention Phase 3 established** —
  `events.timestamp_utc` is read as-is; no new time-zone handling was
  introduced.
- **`validation.py` and the collector are untouched.**

## Files

- `feature_engineering.py` — CLI entry point/orchestrator: reads real
  events, groups by user + time window, calls the feature functions,
  persists results, prints a summary and (optionally) the data-quality
  report.
- `features.py` — pure, unit-tested feature calculations (no DB access).
- `windowing.py` — pure time-window boundary logic (hourly/daily).
- `user_identity.py` — resolves a stable `user_id` from an event.
- `anomaly_detection.py` — endpoint/user-scoped feature aggregation,
  Isolation Forest training, model loading, staleness and scoring.
- `model_storage.py` — versioned local/Azure artifact storage, metadata,
  existence/listing operations, and pre-deserialization integrity validation.
- `demo_anomaly_detection.py` — isolated synthetic normal-vs-unusual
  demonstration through the same feature and model functions.
- `baseline_stats.py` — per-user descriptive statistics (mean/median/
  stdev/min/max) over stored feature windows — **not** anomaly detection.
- `data_quality.py` — data-sufficiency report generator (Phase 5).
- `collection_status.py` — Phase 6A: read-only ML-readiness report,
  built on top of `data_quality.py`/`baseline_stats.py`/`user_identity.py`
  (reused, not reimplemented), ending in a `READY_FOR_ML` /
  `INSUFFICIENT_REAL_DATA` decision.
- `user_classification_diagnostics.py` — Phase 6A.1: read-only, per-account
  report explaining exactly why each account seen in the real data is or
  isn't treated as a human candidate. Reuses
  `log-collector/event_parser.classify_account()` and
  `ACCOUNT_TYPE_EXPLANATIONS` directly rather than re-deriving the logic.
- `FEATURES.md` — the feature dictionary: every feature's meaning,
  source category, calculation, unit, observed-vs-derived status, and
  limitations.

## The behavioral unit: user_id + time window

`user_id` is resolved per event as: `user_sid` (preferred — stable even if
a display name changes) → `domain\username` → `username` alone → `"unknown"`
(only if an event has neither, which should be rare).

**Window size: daily by default**, selectable via `--window-size
hourly|daily`. Daily was chosen because the real, authorized data volumes
collected so far in this project (tens of events per test run) would make
hourly windows mostly empty or single-event — not enough to be meaningful.
Daily windows aggregate enough real activity to be interpretable now, while
the code fully supports switching to hourly once data volume grows (see
`windowing.py`).

## Missing data vs. true zero — the rule this project follows

Every category-specific feature (authentication/file/process/device/
download) follows one rule: **if that category has never been observed
anywhere in the entire stored event history, its features are `None`**
(the audit policy was likely never enabled — genuinely unavailable
telemetry, not "nothing happened"). **If the category HAS been observed
somewhere in the database, then a window with zero matching events for
that user gets a real `0`** — the pipeline was capturing that category
during at least some period, so an empty window is treated as a real
observation of no activity.

**Documented simplification:** this is an all-or-nothing global flag per
category (computed once from the whole dataset), not a precise per-window
audit-policy-active history — this project does not track when an audit
policy was toggled on/off over time. If you enable file-activity auditing
partway through your data collection, all windows (including ones before
you enabled it) will show real `0`s for file features rather than `None`s,
which is a known approximation. This is stated here rather than silently
assumed to be exact.

## Run — compute features from real stored events

```powershell
cd ml-service
python feature_engineering.py --window-size daily
```

Example of the printed summary shape (fields are real counts from your
actual database — this is the format, not a promise of these exact numbers):

```json
{
  "pipeline_summary": {
    "events_read": 0,
    "users_found": 0,
    "time_windows_processed": 0,
    "feature_records_inserted": 0,
    "feature_records_updated": 0,
    "category_availability": {
      "authentication": false,
      "file_activity": false,
      "process_activity": false,
      "device_activity": false,
      "download_related": false
    },
    "window_size": "daily",
    "storage_location": "sqlite:///.../data/app.db"
  }
}
```

### Also print the full data-quality report

```powershell
python feature_engineering.py --window-size daily --data-quality-report
```

### Inspect stored feature records

```powershell
python feature_engineering.py --show 20
python feature_engineering.py --show 20 --user-id "S-1-5-21-..."
```

### Inspect per-user baseline statistics

```powershell
python feature_engineering.py --baselines
python feature_engineering.py --baselines --user-id "S-1-5-21-..."
```

Reads only already-stored feature records — does not recompute anything.

## Data-quality report

`generate_data_quality_report()` (in `data_quality.py`) reports, from the
real database: total events, events by category, events by user, coverage
period (earliest/latest real event timestamp), missing important fields
(username/computer_name), how many users/windows meet rough
"enough-to-analyze" thresholds, and explicit warnings when the dataset is
too small — this is meant to answer "do we have enough real data to move
to Phase 6?", not to train or evaluate anything.

## Phase 6A — is there enough real data to move to ML?

### Why this matters

A model trained on too little, too narrow, or non-human data would learn
nothing meaningful — or worse, learn artifacts of the test process itself
(e.g. "this account only ever appears in short bursts during testing")
and call that a behavioral baseline. Phase 6A exists to make that judgment
call transparent and evidence-based instead of assumed.

### Check ML readiness

```powershell
cd ml-service
python feature_engineering.py --collection-status
```

This is **read-only** — it does not recompute or store anything (unlike
the default `feature_engineering.py` run), and never deletes or overwrites
existing events or feature rows. It inspects whatever `events` and
`behavior_features` rows already exist and prints a full report ending in
one decision field: `"READY_FOR_ML"` or `"INSUFFICIENT_REAL_DATA"`.

**Illustrative output shape only — not a real result:**

```json
{
  "decision": "INSUFFICIENT_REAL_DATA",
  "technical_sufficiency": { "is_sufficient": true, "reasons": [] },
  "research_sufficiency": {
    "is_sufficient": false,
    "qualifying_users": [],
    "reasons": ["<real, specific reasons — not this placeholder text>"]
  },
  "basic_inspection": { "total_events": 0, "...": "..." },
  "user_coverage": { "<user_id>": { "events_count": 0, "...": "..." } },
  "event_coverage": { "authentication": { "event_count": 0, "...": "..." } },
  "feature_coverage": { "<feature_name>": { "populated_in_any_window": false } }
}
```

I actually ran this command against this project's real database; it
returned `INSUFFICIENT_REAL_DATA` with real, specific reasons (all
existing events are `uncategorized` application-log test data, not
authentication/file/process/device activity, and there is no
identifiable human user yet) — see the worked example in the project's
Phase 6A implementation notes.

### Technical sufficiency vs. research sufficiency

These answer two different questions and are reported separately:

| | Technical sufficiency | Research sufficiency |
|---|---|---|
| **Question** | Does the pipeline work end-to-end? | Is there enough real behavioral history to mean anything? |
| **Criteria** | At least 1 stored event AND at least 1 `behavior_features` row exists. | ALL of: at least one human-candidate user (see below); at least `MIN_TOTAL_EVENTS_FOR_ANALYSIS` (50) categorized (non-uncategorized) events overall; at least one human-candidate user with ALL of >= `MIN_EVENTS_PER_USER_FOR_ANALYSIS` (20) events, >= `MIN_WINDOWS_PER_USER_FOR_BASELINE` (3) behavioral windows, AND >= `MIN_ACTIVE_DAYS_FOR_RESEARCH` (3) distinct active days. |
| **Satisfied by** | A handful of test events from any source. | Real, multi-day, attributable human activity. |

`READY_FOR_ML` requires **both** to be true — the command never reports
readiness just because it ran without error.

**Human-candidate users:** an account only counts if its `account_type`
(from Phase 2/4's `classify_account()`) is `"human_or_unknown"`. Accounts
identified as `system`, `local_service`, `network_service`, or
`computer_account` (via well-known SIDs or name patterns) are explicitly
excluded from research sufficiency, per this phase's requirement not to
treat service accounts as human users. Note the honesty limit here too:
`"human_or_unknown"` is the best this project can assert — it is not
positive proof of a human, only the absence of a positive service-account
signal.

### Event, user, and feature coverage in the report

- **`event_coverage`**: per known category (authentication, file_activity,
  process_activity, device_activity, download_related), real event count,
  the real event IDs actually seen, and whether that category individually
  clears `MIN_EVENTS_PER_CATEGORY_FOR_ANALYSIS` (20) — plus an
  `uncategorized` bucket for anything not in a known category.
- **`user_coverage`**: per resolved `user_id` — event count, distinct
  computers, most-common `account_type`, earliest/latest real timestamp,
  span in days, count of distinct active calendar days, and behavioral
  window count (for the `--window-size` in effect).
- **`feature_coverage`**: for a representative feature per category, whether
  it's populated in any stored window at all, and which users have enough
  per-user history (via `baseline_stats.compute_user_baselines`) for that
  specific feature's baseline to be meaningful.

Nothing here fabricates a missing value — an empty/zero result is reported
as exactly that, with the reason stated in `warnings`/`reasons`.

### Collecting more real data: three different things, not one

- **Initial validation data** (what exists so far): a few test runs used to
  confirm the pipeline mechanically works (parsing, storage, feature
  computation). This is what's in the database right now. It does **not**
  represent anyone's normal behavior and should not be treated as such.
- **Historical baseline data**: real activity collected over multiple
  distinct days (this project's `MIN_ACTIVE_DAYS_FOR_RESEARCH` = 3 as a
  floor, though more is better) for the same real, authorized user,
  establishing what "normal" looks like for them. This is what
  `research_sufficiency` in `--collection-status` is checking for.
- **Anomaly evaluation data**: real activity collected *after* a baseline
  exists, used later (Phase 6B+) to see whether new behavior looks
  consistent with or different from that baseline. Not collected or used
  in this phase.

Do not treat a few minutes (or even a single day) of activity as a
baseline — the active-days and per-user-window thresholds above exist
specifically to prevent that.

### Generating real activity for each category

Use the exact same authorized, controlled actions already documented in
[`log-collector/README.md`](../log-collector/README.md) (Verifying the
output is genuine → per-category steps), repeated **across multiple
separate days** rather than once:

- **Authentication**: normal login, normal logout, and (only if authorized
  on your test machine) a deliberate failed login attempt.
- **File activity**: create, modify (edit and save), rename, and delete a
  test file **inside the one folder you configured with
  `scripts/enable_file_activity_audit.ps1`** — never a personal/unrelated
  folder, and never enable auditing system-wide. File contents are never
  read, copied, or stored by this project at any phase.
- **Process activity**: launch and close ordinary applications (e.g.
  Notepad, Calculator).
- **Device activity**: connect (and, if you want to test the documented
  connect-only limitation, note that disconnect isn't captured) an
  authorized USB device.

After each real session, run:

```powershell
cd log-collector
python collector.py --categories authentication,file_activity,process_activity,device_activity --limit 50

cd ..\ml-service
python feature_engineering.py --window-size daily
python feature_engineering.py --collection-status
```

Repeat on different real days until `--collection-status` reports
`READY_FOR_ML`.

## Phase 6A.1 — verifying human-user classification before collecting more data

Before committing to multiple days of real collection, this phase checked
whether `classify_account()` (in `log-collector/event_parser.py`) correctly
identifies a genuine human Windows account, and diagnosed why the database
had zero human candidates.

### What was actually wrong

**Nothing in the classification logic was misclassifying real
authentication/file/process/device data.** The 5 stored rows are all
`event_id 1001` from the **Application** log (a Windows Component-Based
Servicing failure event, collected during earlier Phase 2/3 smoke-testing
specifically because it doesn't require Administrator access) — this
event type has no `SubjectUserName`/`TargetUserName` field at all in
Microsoft's own schema for it. `account_type` correctly comes out as
`"unknown"` (no username/SID present at all) and `event_category` is
correctly `None`/`uncategorized` (event ID 1001 isn't one of this
project's supported authentication/file/process/device event IDs). This
was confirmed by querying `data/app.db` directly. **No fix was needed for
this specific data** — it's accurately reported as non-human, non-relevant
test data, exactly as it should be.

### What WAS fixed, and why it's a real (if not yet triggered) gap

While auditing `classify_account()` for how it will behave once real
Security-log events ARE collected, one genuine gap was found: Windows
automatically creates **per-session virtual service accounts** for the
Desktop Window Manager (`DWM-<n>`, SID prefix `S-1-5-90-0-`) and Font
Driver Host (`UMFD-<n>`, SID prefix `S-1-5-96-0-`) — these appear
constantly in real 4624 logon events on any modern Windows 10/11 machine,
and the *previous* logic had no rule for them, so they would have fallen
through to `human_or_unknown` and been miscounted as human activity. This
was fixed with the smallest safe, additive change: two new well-known,
Microsoft-documented identity patterns (plus `ANONYMOUS LOGON`, SID
`S-1-5-7`) are now excluded, alongside the existing SYSTEM/LOCAL
SERVICE/NETWORK SERVICE/computer-account checks. **No behavior changed for
any account that isn't one of these specific, documented non-human
identities** — a real human account is still classified exactly as before
(all 85 pre-existing tests still pass unchanged).

### Diagnose account classification

```powershell
cd ml-service
python feature_engineering.py --user-classification-status
```

Read-only — reports every distinct `(domain, username)` seen in the real
stored events, its `account_type`, whether it's a human candidate, and
(if not) the exact reason why, reusing
`event_parser.ACCOUNT_TYPE_EXPLANATIONS` as the single source of truth for
that reasoning. Does not print raw SIDs or `raw_event_data` — only a
`sid_present` boolean, to avoid exposing more identifying detail than the
diagnostic purpose requires.

I ran this against the real database; it reported exactly what was
expected: 1 distinct account (all 5 rows share no username/SID at all),
`account_type: "unknown"`, `is_human_candidate: false`,
`human_candidate_account_count: 0` — consistent with, and explaining,
Phase 6A's `INSUFFICIENT_REAL_DATA` result.

## Privacy

Unchanged from Phase 4: no passwords, private messages, document contents,
browser passwords, cookies, keystrokes, or screenshots are collected or
derived here. Feature values are aggregate counts/ratios/statistics over
metadata already stored by Phase 2-4 — nothing new is read from the
Windows machine in this phase; it only summarizes what's already in
`data/app.db`.

## Known limitations

- **File action granularity** stays coarse (from Phase 4) — no
  `files_created`/`files_modified` features are computed, because that
  distinction isn't reliably available from the source events. Only
  `files_accessed`, `files_deleted`, `files_handle_requested` are computed.
- **Off-hours** uses UTC hour boundaries (9:00-17:00 UTC), not each user's
  true local time (not reliably known) — an approximation.
- **Session-based features** (`activity_after_failed_login_count`,
  `avg_files_per_session`) only look within a single time window — activity
  crossing a window boundary is not linked across windows.
- **Category availability** is a global, all-or-nothing flag (see above),
  not a precise per-window audit-policy history.
- **`unique_process_names`** (mentioned in the original feature list) is
  consolidated into the numeric `unique_process_count` — a raw list of
  names isn't a scalar ML-ready feature; see `FEATURES.md`.

## Remaining limitations

- No evaluation on a suitable labeled dataset, no accuracy/precision/
  recall/F1 claims, no probability calibration, and no claim that an
  anomaly is a confirmed incident.
- No One-Class SVM or Local Outlier Factor implementation. No Azure
  deployment.
- `baseline_stats.py` computes plain descriptive statistics only — it is
  separate from this detector and makes no anomaly judgments.
- `collection_status.py` only reports a readiness decision — it does not
  gate, block, or automatically trigger anything; a human still decides
  when to train. The API training operation separately enforces a
  minimum of 20 completed windows per profile.
- Synthetic data is used only by the explicitly synthetic demonstration and
  deterministic tests; it is never inserted into the real event database or
  default model-artifact directory.
