"""
Data-quality / sufficiency report generator for the real stored event and
feature history. Read-only, no computation happens elsewhere is repeated
here — this module only summarizes what compute_events / feature records
already contain, to help decide whether there's enough real data to move
toward Phase 6 (ML). It does not train, score, or evaluate anything.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime

from user_identity import resolve_user_id

# Below this many total events, or this many events for a given user,
# per-user statistics are unlikely to be meaningful yet — thresholds are
# reported, not enforced (nothing here blocks or hides work, it only labels
# in the report).
MIN_TOTAL_EVENTS_FOR_ANALYSIS = 50
MIN_EVENTS_PER_USER_FOR_ANALYSIS = 20
MIN_WINDOWS_PER_USER_FOR_BASELINE = 3


def generate_data_quality_report(events: list[dict], feature_records: list[dict]) -> dict:
    total_events = len(events)
    events_by_category: Counter = Counter(e.get("event_category") or "uncategorized" for e in events)
    events_by_user: Counter = Counter()
    missing_username = 0
    missing_computer_name = 0

    timestamps = []
    for e in events:
        # Reuses the same user_id resolution as feature_engineering.py
        # (ml-service/user_identity.py) so counts here line up exactly with
        # the users behavior_features rows are keyed by.
        user_id = resolve_user_id(e)
        events_by_user[user_id] += 1
        if not e.get("username"):
            missing_username += 1
        if not e.get("computer_name"):
            missing_computer_name += 1
        if e.get("timestamp_utc"):
            try:
                timestamps.append(datetime.fromisoformat(e["timestamp_utc"]))
            except ValueError:
                pass

    coverage = None
    if timestamps:
        coverage = {
            "earliest_event_utc": min(timestamps).isoformat(),
            "latest_event_utc": max(timestamps).isoformat(),
            "span_days": (max(timestamps) - min(timestamps)).total_seconds() / 86400,
        }

    users_with_enough_events = [
        user for user, count in events_by_user.items() if count >= MIN_EVENTS_PER_USER_FOR_ANALYSIS
    ]

    windows_by_user: Counter = Counter(r["user_id"] for r in feature_records)
    users_with_enough_windows = [
        user for user, count in windows_by_user.items() if count >= MIN_WINDOWS_PER_USER_FOR_BASELINE
    ]

    warnings = []
    if total_events < MIN_TOTAL_EVENTS_FOR_ANALYSIS:
        warnings.append(
            f"Only {total_events} total real event(s) stored — below the "
            f"{MIN_TOTAL_EVENTS_FOR_ANALYSIS}-event threshold this report uses as a rough "
            "'enough to start looking for patterns' floor. Continue collecting real data."
        )
    if not users_with_enough_events:
        warnings.append(
            f"No user currently has >= {MIN_EVENTS_PER_USER_FOR_ANALYSIS} stored events — "
            "per-user behavioral analysis will be unreliable until at least one user does."
        )
    if not users_with_enough_windows:
        warnings.append(
            f"No user currently has >= {MIN_WINDOWS_PER_USER_FOR_BASELINE} computed time "
            "windows — per-user baseline statistics (see baseline_stats.py) cannot be "
            "computed for anyone yet."
        )

    return {
        "total_events": total_events,
        "events_by_category": dict(events_by_category),
        "events_by_user": dict(events_by_user),
        "distinct_users": len(events_by_user),
        "missing_username_count": missing_username,
        "missing_computer_name_count": missing_computer_name,
        "coverage_period": coverage,
        "total_feature_windows": len(feature_records),
        "users_with_enough_events_for_analysis": users_with_enough_events,
        "users_with_enough_windows_for_baseline": users_with_enough_windows,
        "warnings": warnings,
        "thresholds_used": {
            "min_total_events_for_analysis": MIN_TOTAL_EVENTS_FOR_ANALYSIS,
            "min_events_per_user_for_analysis": MIN_EVENTS_PER_USER_FOR_ANALYSIS,
            "min_windows_per_user_for_baseline": MIN_WINDOWS_PER_USER_FOR_BASELINE,
        },
    }
