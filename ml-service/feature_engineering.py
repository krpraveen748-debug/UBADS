"""
Phase 5 orchestrator: REAL EVENTS -> TIME WINDOW -> USER AGGREGATION ->
BEHAVIORAL FEATURES -> FEATURE DATASET (SQLite) -> DATA QUALITY REPORT.

Reuses the existing Phase 2-4 layers directly rather than reimplementing
anything:
  - storage.py (log-collector/)   : reads real stored events, persists
                                     computed feature rows, in the SAME
                                     data/app.db used since Phase 3.
  - event_record_to_dict()        : the exact normalized-event shape
                                     already established — not reinvented.
  - validation's UTC convention   : timestamps are read as the UTC
                                     `timestamp_utc` column Phase 3 already
                                     computed, never re-derived.

This file only orchestrates: grouping, calling the pure functions in
features.py/windowing.py/user_identity.py, and calling storage.py to
persist results. It contains no SQL itself beyond what storage.py exposes.

`log-collector/` and `ml-service/` are both hyphenated directory names (not
valid Python package names), so this file adds log-collector's path to
sys.path explicitly to import its `storage` module directly — the same
pattern collector.py could have used, made explicit here for clarity.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
_LOG_COLLECTOR_DIR = PROJECT_ROOT / "log-collector"
if str(_LOG_COLLECTOR_DIR) not in sys.path:
    sys.path.insert(0, str(_LOG_COLLECTOR_DIR))

from storage import (  # noqa: E402  (import after sys.path setup, see docstring)
    DATABASE_URL,
    SessionLocal,
    event_record_to_dict,
    feature_record_to_dict,
    get_all_events,
    get_feature_records,
    init_db,
    save_feature_record,
)

from baseline_stats import compute_user_baselines  # noqa: E402
from collection_status import generate_collection_status  # noqa: E402
from data_quality import generate_data_quality_report  # noqa: E402
from features import (  # noqa: E402
    compute_authentication_features,
    compute_cross_category_features,
    compute_device_activity_features,
    compute_download_related_features,
    compute_file_activity_features,
    compute_process_activity_features,
    compute_time_features,
)
from user_classification_diagnostics import generate_user_classification_report  # noqa: E402
from user_identity import resolve_user_id  # noqa: E402
from windowing import VALID_WINDOW_SIZES, window_bounds  # noqa: E402

logger = logging.getLogger("feature_engineering")

CATEGORIES = ("authentication", "file_activity", "process_activity", "device_activity", "download_related")

_AUTH_NULL = {
    "successful_login_count": None,
    "failed_login_count": None,
    "login_failure_ratio": None,
    "unique_login_hours": None,
    "first_login_hour": None,
    "last_login_hour": None,
    "average_login_hour": None,
    "logoff_count": None,
}
_FILE_NULL = {
    "files_accessed": None,
    "files_deleted": None,
    "files_handle_requested": None,
    "unique_file_extensions": None,
    "unique_directories": None,
    "file_activity_count": None,
}
_PROCESS_NULL = {
    "process_count": None,
    "unique_process_count": None,
    "process_activity_frequency": None,
}
_DEVICE_NULL = {"device_event_count": None, "unique_devices": None, "new_device_count": None}
_DOWNLOAD_NULL = {
    "download_related_event_count": None,
    "download_related_file_count": None,
    "download_related_activity_frequency": None,
}


def compute_category_availability(events: list[dict]) -> dict[str, bool]:
    """Whether each category has EVER been observed anywhere in the stored
    history — decides None (never audited/collected) vs. real 0 (audited,
    just no activity this window). See features.py module docstring."""
    present = {e.get("event_category") for e in events}
    return {cat: cat in present for cat in CATEGORIES}


def _most_common(values: list[str | None]) -> str | None:
    cleaned = [v for v in values if v]
    if not cleaned:
        return None
    return Counter(cleaned).most_common(1)[0][0]


def group_events_by_user_and_window(events: list[dict], window_size: str) -> dict:
    """Returns {user_id: {window_start_datetime: [events...]}}."""
    grouped: dict[str, dict] = defaultdict(lambda: defaultdict(list))
    for event in events:
        ts_str = event.get("timestamp_utc")
        if not ts_str:
            continue
        ts = datetime.fromisoformat(ts_str)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        user_id = resolve_user_id(event)
        window_start, _ = window_bounds(ts, window_size)
        grouped[user_id][window_start].append(event)
    return grouped


def compute_feature_record(
    user_id: str,
    window_start: datetime,
    window_end: datetime,
    window_size: str,
    events_in_window: list[dict],
    category_availability: dict[str, bool],
) -> dict:
    auth_features = (
        compute_authentication_features(events_in_window)
        if category_availability["authentication"]
        else dict(_AUTH_NULL)
    )
    file_features = (
        compute_file_activity_features(events_in_window)
        if category_availability["file_activity"]
        else dict(_FILE_NULL)
    )
    process_features = (
        compute_process_activity_features(events_in_window, window_size)
        if category_availability["process_activity"]
        else dict(_PROCESS_NULL)
    )
    download_features = (
        compute_download_related_features(events_in_window, window_size)
        if category_availability["download_related"]
        else dict(_DOWNLOAD_NULL)
    )
    time_features = compute_time_features(events_in_window, window_start)
    cross_features = compute_cross_category_features(
        events_in_window, category_availability, auth_features, file_features, process_features
    )

    record = {
        "user_id": user_id,
        "username": _most_common([e.get("username") for e in events_in_window]),
        "domain": _most_common([e.get("domain") for e in events_in_window]),
        "account_type": _most_common([e.get("account_type") for e in events_in_window]),
        "window_size": window_size,
        "window_start": window_start,
        "window_end": window_end,
        **auth_features,
        **file_features,
        **process_features,
        **download_features,
        **time_features,
        **cross_features,
    }
    return record


def run_feature_engineering(window_size: str = "daily") -> dict:
    """Full pipeline: read all real stored events, compute per-user/window
    features, upsert into behavior_features. Returns a summary dict."""
    init_db()
    with SessionLocal() as session:
        events = [event_record_to_dict(r) for r in get_all_events(session)]

    category_availability = compute_category_availability(events)
    grouped = group_events_by_user_and_window(events, window_size)

    inserted = 0
    updated = 0
    windows_processed = 0
    device_seen_by_user: dict[str, set] = defaultdict(set)

    with SessionLocal() as session:
        for user_id, windows in grouped.items():
            for window_start in sorted(windows.keys()):
                events_in_window = windows[window_start]
                _, window_end = window_bounds(window_start, window_size)

                device_features, new_device_keys = (
                    compute_device_activity_features(events_in_window, device_seen_by_user[user_id])
                    if category_availability["device_activity"]
                    else (dict(_DEVICE_NULL), set())
                )
                device_seen_by_user[user_id] |= new_device_keys

                record = compute_feature_record(
                    user_id, window_start, window_end, window_size, events_in_window, category_availability
                )
                record.update(device_features)

                outcome = save_feature_record(session, record)
                windows_processed += 1
                if outcome == "inserted":
                    inserted += 1
                else:
                    updated += 1

    logger.info(
        "Processed %d event(s) across %d user(s) into %d window(s): %d inserted, %d updated.",
        len(events),
        len(grouped),
        windows_processed,
        inserted,
        updated,
    )

    return {
        "events_read": len(events),
        "users_found": len(grouped),
        "time_windows_processed": windows_processed,
        "feature_records_inserted": inserted,
        "feature_records_updated": updated,
        "category_availability": category_availability,
        "window_size": window_size,
        "storage_location": DATABASE_URL,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compute behavioral features from real stored Windows activity events."
    )
    parser.add_argument(
        "--window-size",
        choices=VALID_WINDOW_SIZES,
        default="daily",
        help="Time window size for aggregation (default: daily). See windowing.py for why.",
    )
    parser.add_argument(
        "--show",
        type=int,
        default=None,
        metavar="N",
        help="Instead of recomputing, print the N most recent stored feature records.",
    )
    parser.add_argument("--user-id", type=str, default=None, help="Filter --show/--baselines to one user_id.")
    parser.add_argument(
        "--baselines",
        action="store_true",
        help="Print per-user baseline statistics computed from stored feature records (no recomputation).",
    )
    parser.add_argument(
        "--data-quality-report",
        action="store_true",
        help="Also print the full data-quality/sufficiency report.",
    )
    parser.add_argument(
        "--collection-status",
        action="store_true",
        help=(
            "Read-only: report whether enough real data has been collected to "
            "proceed to ML (Phase 6A). Does NOT recompute or store anything — "
            "inspects existing events and behavior_features rows only."
        ),
    )
    parser.add_argument(
        "--user-classification-status",
        action="store_true",
        help=(
            "Read-only (Phase 6A.1): report every distinct account seen in the "
            "real stored events, its classification, and why it is or isn't "
            "treated as a human candidate. Does not modify anything."
        ),
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress INFO-level logging.")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    init_db()

    if args.user_classification_status:
        with SessionLocal() as session:
            events = [event_record_to_dict(r) for r in get_all_events(session)]
        report = generate_user_classification_report(events)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    if args.collection_status:
        with SessionLocal() as session:
            events = [event_record_to_dict(r) for r in get_all_events(session)]
            feature_records = [
                feature_record_to_dict(r) for r in get_feature_records(session, limit=100000)
            ]
        status = generate_collection_status(events, feature_records, window_size=args.window_size)
        print(json.dumps(status, indent=2, ensure_ascii=False, default=str))
        logger.info("Collection status decision: %s", status["decision"])
        return 0

    if args.show is not None:
        with SessionLocal() as session:
            records = [
                feature_record_to_dict(r)
                for r in get_feature_records(session, user_id=args.user_id, limit=args.show)
            ]
        print(json.dumps(records, indent=2, ensure_ascii=False))
        return 0

    if args.baselines:
        with SessionLocal() as session:
            records = [
                feature_record_to_dict(r)
                for r in get_feature_records(session, user_id=args.user_id, limit=100000)
            ]
        by_user: dict[str, list[dict]] = defaultdict(list)
        for r in records:
            if r["window_size"] == args.window_size:
                by_user[r["user_id"]].append(r)
        baselines = {user_id: compute_user_baselines(recs) for user_id, recs in by_user.items()}
        print(json.dumps(baselines, indent=2, ensure_ascii=False))
        return 0

    summary = run_feature_engineering(window_size=args.window_size)
    output = {"pipeline_summary": summary}

    if args.data_quality_report:
        with SessionLocal() as session:
            events = [event_record_to_dict(r) for r in get_all_events(session)]
            feature_records = [
                feature_record_to_dict(r) for r in get_feature_records(session, limit=100000)
            ]
        output["data_quality_report"] = generate_data_quality_report(events, feature_records)

    print(json.dumps(output, indent=2, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
