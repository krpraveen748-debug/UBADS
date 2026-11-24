# Feature Dictionary — Phase 5

Every column in `behavior_features` (defined in
`log-collector/storage.py`), one row per `(user_id, window_start,
window_size)`. **Missing-data rule** (see `ml-service/README.md` for full
explanation): `None` = the category was never observed anywhere in the
database (genuinely unavailable telemetry). A real `0` = the category is
observed elsewhere in the data; this specific window just had none.

## Identity / window columns (always present)

| Column | Meaning |
|---|---|
| `user_id` | `user_sid` (preferred) → `domain\username` → `username` → `"unknown"`. |
| `username`, `domain`, `account_type` | Most common non-null value across this window's events for this user (descriptive only, not used as ML input). |
| `window_size` | `"hourly"` or `"daily"`. |
| `window_start`, `window_end` | UTC window boundaries (`window_end` exclusive). |
| `computed_at` | When this row was computed/last updated by the pipeline. |

## Always-computable features

| Feature | Meaning | Calculation | Unit | Observed/Derived | Limitations |
|---|---|---|---|---|---|
| `total_activity_count` | All real events for this user in this window, any category | `COUNT(*)` | count | Observed | None. |
| `number_of_categories_active` | How many distinct known categories appear in this window | Count of distinct `event_category` values, excluding `uncategorized` | count (0-5) | Derived | None. |
| `day_of_week` | Day of the window start | `window_start.weekday()` (0=Mon..6=Sun) | ordinal | Derived | UTC calendar day, not the user's local day. |
| `is_weekend` | Whether `day_of_week` is Sat/Sun | `1` if `day_of_week >= 5` else `0` | boolean | Derived | Same UTC caveat as above. |
| `off_hours_activity_count` | Events outside 9:00-17:00 UTC | Count of events whose UTC hour is `<9` or `>=17` | count | Derived | UTC hour is an approximation of "business hours" — not the user's true local time, which isn't reliably known. |
| `distinct_active_hours` | Spread of activity across the day | Count of distinct UTC hours with >=1 event | count (0-24) | Derived | Same UTC caveat. |

## Authentication features (`None` if `authentication` never observed)

| Feature | Meaning | Calculation | Unit | Obs/Der | Limitations |
|---|---|---|---|---|---|
| `successful_login_count` | Successful logons (4624) this window | Count `event_type == "successful_logon"` | count | Observed | None. |
| `failed_login_count` | Failed logons (4625) this window | Count `event_type == "failed_logon"` | count | Observed | None. |
| `login_failure_ratio` | Fraction of logon attempts that failed | `failed / (failed + successful)` | ratio [0,1] | Derived | `None` (not `0`) if there were zero attempts this window — undefined, not zero. |
| `unique_login_hours` | Distinct hours-of-day with a logon attempt | Count of distinct UTC hours among successful+failed logons | count | Derived | UTC hour. |
| `first_login_hour` / `last_login_hour` | Earliest/latest logon-attempt hour | `min`/`max` of those hours | hour (0-23) | Derived | `None` if no attempts this window. |
| `average_login_hour` | Mean logon-attempt hour | `mean()` of those hours | hour (float) | Derived | Circular-mean issues near midnight are not corrected (e.g. 23:00 and 01:00 average to 12:00, not 00:00) — a known simplification. |
| `logoff_count` | Logoff events (4634/4647) this window | Count `event_type in (logoff, user_initiated_logoff)` | count | Observed | None. |

## File activity features (`None` if `file_activity` never observed)

| Feature | Meaning | Calculation | Unit | Obs/Der | Limitations |
|---|---|---|---|---|---|
| `files_accessed` | 4663 events this window | Count `file_action == "accessed"` | count | Observed | Coarse — "accessed" doesn't distinguish read from write; see Phase 4 limitation. |
| `files_deleted` | 4660 events this window | Count `file_action == "deleted"` | count | Observed | None. |
| `files_handle_requested` | 4656 events this window | Count `file_action == "handle_requested"` | count | Observed | Precedes an access; may double-count activity also reflected in `files_accessed`. |
| `unique_file_extensions` | Variety of file types touched | Count of distinct non-null `file_extension` | count | Derived | Extension only, not deeper file-type detection. |
| `unique_directories` | Variety of locations touched | Count of distinct `dirname(file_path)` | count | Derived | Path-string based; symlinks/junctions not resolved. |
| `file_activity_count` | Total file-activity rows this window | Count of events with `file_action` set (includes `download_related` rows too) | count | Observed | Deliberately includes download-classified rows — see `download_related_event_count` for that subset alone. |

**Not computed:** `files_created`, `files_modified` — Phase 4's
`file_action` values (`handle_requested`/`accessed`/`deleted`) cannot
reliably distinguish creation from modification without decoding
`AccessMask`, which Phase 4 documented as unreliable to do generically.
Computing these would mean inventing data not actually available.

## Process activity features (`None` if `process_activity` never observed)

| Feature | Meaning | Calculation | Unit | Obs/Der | Limitations |
|---|---|---|---|---|---|
| `process_count` | Processes started this window | Count of `process_activity` events | count | Observed | None. |
| `unique_process_count` | Variety of programs run | Count of distinct non-null `process_name` | count | Derived | Consolidates the originally-separate "unique_process_names" idea — a raw name list isn't a scalar ML feature. |
| `process_activity_frequency` | Rate of process launches | `process_count / window_duration_hours` (24 for daily, 1 for hourly) | processes/hour | Derived | None. |

## Device activity features (`None` if `device_activity` never observed)

| Feature | Meaning | Calculation | Unit | Obs/Der | Limitations |
|---|---|---|---|---|---|
| `device_event_count` | Device-recognition (6416) events this window | Count of `device_activity` events | count | Observed | Connect-only — see Phase 4 (no disconnect signal). |
| `unique_devices` | Distinct devices seen this window | Count of distinct `(device_id or device_description)` | count | Derived | Falls back to description only when no `device_id` is present. |
| `new_device_count` | Devices never seen before for this user | Count of this window's device keys not present in that user's EARLIER windows (processed in chronological order) | count | Derived | Only as good as the real historical data seen so far — a device seen for the first time in the collector's history looks "new" even if it was actually connected before collection started. |

## Download-related features (`None` if `download_related` never observed)

| Feature | Meaning | Calculation | Unit | Obs/Der | Limitations |
|---|---|---|---|---|---|
| `download_related_event_count` | File-activity events under the configured downloads folder | Count of events with `event_category == "download_related"` | count | **Derived (inference)** | Folder-location based only — not a confirmed browser download; see Phase 4 "Download activity". |
| `download_related_file_count` | Distinct files involved | Count of distinct `file_path` among those events | count | Derived (inference) | Same caveat. |
| `download_related_activity_frequency` | Rate of download-related activity | `download_related_event_count / window_duration_hours` | events/hour | Derived (inference) | Same caveat. |

## Cross-category features

| Feature | Meaning | Calculation | Unit | Obs/Der | Limitations |
|---|---|---|---|---|---|
| `authentication_to_file_activity_ratio` | Logons relative to file activity | `(successful+failed logins) / file_activity_count` | ratio | Derived | `None` if either category unavailable, or if `file_activity_count == 0` this window (avoids divide-by-zero; not the same as a ratio of `0`). |
| `authentication_to_process_activity_ratio` | Logons relative to process launches | `(successful+failed logins) / process_count` | ratio | Derived | Same divide-by-zero handling as above. |
| `activity_after_failed_login_count` | Non-auth events shortly after a failed logon | Count of file/process/device events within 300 seconds after any failed_logon, **within the same window only** | count | Derived | Cross-window sequences (e.g. failed logon at 23:58, activity at 00:02) are not linked — documented scope limit. |
| `avg_files_per_session` | Average file activity per approximate login session | Mean file-activity count between a `successful_logon` and the next logoff/logon, **within the same window only**; sessions with no observed end in-window are excluded | files/session | Derived | Approximate session boundaries; cross-window sessions are excluded rather than guessed. |

## Baseline statistics (separate table concept, not stored as columns)

`baseline_stats.compute_user_baselines()` computes mean/median/stdev/min/
max **per user**, over that user's own stored window history, for a subset
of the numeric features above (see `_BASELINE_FEATURES` in
`baseline_stats.py`). Requires at least 3 windows of real data per user (or
per feature) — otherwise reports `insufficient_data: true` rather than
computing a baseline from too little history. This is descriptive
statistics only — no anomaly judgment is made from it in this phase.
