"""
Phase 6A — Real Data Collection Validation.

Read-only report: inspects the real events and behavior_features rows
already stored (never modifies, deletes, or invents anything) and answers
one question transparently — "do we have enough REAL data to move to
Phase 6B (ML)?" It reuses data_quality.py, user_identity.py, and
baseline_stats.py rather than recomputing any of that logic separately.

Two distinct kinds of "enough" are reported separately, because they mean
different things:

  - TECHNICAL SUFFICIENCY: the pipeline itself works end-to-end (events
    exist, at least one behavioral window was computed). This says nothing
    about whether the data is behaviorally meaningful — five test events
    from an application-log smoke test satisfy this.
  - RESEARCH SUFFICIENCY: there is enough real, attributable, multi-day
    human-user history for the resulting features/baselines to mean
    anything. This is the bar that actually matters before training a
    model on this data.

The final decision is `READY_FOR_ML` only when BOTH are satisfied — never
just because the command ran successfully.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime

from baseline_stats import MIN_WINDOWS_FOR_BASELINE, compute_user_baselines
from data_quality import (
    MIN_EVENTS_PER_USER_FOR_ANALYSIS,
    MIN_TOTAL_EVENTS_FOR_ANALYSIS,
    MIN_WINDOWS_PER_USER_FOR_BASELINE,
    generate_data_quality_report,
)
from user_identity import resolve_user_id

# A user is only treated as a candidate real human for RESEARCH sufficiency
# if their account_type is "human_or_unknown" — classify_account() (Phase 4,
# tightened in Phase 6A.1) never asserts certainty that an account is human
# (hence the name), but it DOES positively identify SYSTEM/LOCAL SERVICE/
# NETWORK SERVICE/ANONYMOUS LOGON/per-session virtual (DWM/UMFD)/computer
# accounts by well-known SID or name. We exclude exactly those, per this
# phase's explicit instruction not to treat service accounts as human users.
# See event_parser.ACCOUNT_TYPE_EXPLANATIONS for the full, single-source-of-
# truth reasoning behind each of these labels.
HUMAN_CANDIDATE_ACCOUNT_TYPES = {"human_or_unknown"}
SERVICE_ACCOUNT_TYPES = {
    "system",
    "local_service",
    "network_service",
    "anonymous_logon",
    "virtual_service_account",
    "computer_account",
    "windows_service_account",  # Phase 11: NT SERVICE\<name> (S-1-5-80-*)
}

# A category needs at least this many total real events before its
# per-window features are considered research-usable (same magnitude as
# the per-user threshold in data_quality.py, for consistency).
MIN_EVENTS_PER_CATEGORY_FOR_ANALYSIS = 20

# A meaningful baseline needs history spread across multiple real days, not
# just multiple windows carved out of one single day of activity.
MIN_ACTIVE_DAYS_FOR_RESEARCH = 3

KNOWN_CATEGORIES = ("authentication", "file_activity", "process_activity", "device_activity", "download_related")

# Representative behavioral features checked for population/coverage —
# one from each category plus a cross-category one. Kept short and
# reviewable rather than iterating all ~30 behavior_features columns.
REPRESENTATIVE_FEATURES = (
    "successful_login_count",
    "file_activity_count",
    "process_count",
    "device_event_count",
    "download_related_event_count",
    "total_activity_count",
)


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _user_coverage(events: list[dict], feature_records: list[dict], window_size: str) -> dict:
    per_user: dict[str, dict] = {}
    events_by_user: dict[str, list[dict]] = {}
    for e in events:
        events_by_user.setdefault(resolve_user_id(e), []).append(e)

    windows_by_user: Counter = Counter(
        r["user_id"] for r in feature_records if r.get("window_size") == window_size
    )

    for user_id, user_events in events_by_user.items():
        timestamps = [t for t in (_parse_ts(e.get("timestamp_utc")) for e in user_events) if t is not None]
        computers = {e["computer_name"] for e in user_events if e.get("computer_name")}
        account_types = Counter(e["account_type"] for e in user_events if e.get("account_type"))
        active_days = {t.date() for t in timestamps}

        per_user[user_id] = {
            "events_count": len(user_events),
            "distinct_computers": sorted(computers),
            "account_type": account_types.most_common(1)[0][0] if account_types else None,
            "earliest_event_utc": min(timestamps).isoformat() if timestamps else None,
            "latest_event_utc": max(timestamps).isoformat() if timestamps else None,
            "span_days": (
                (max(timestamps) - min(timestamps)).total_seconds() / 86400 if len(timestamps) > 1 else 0.0
            ),
            "active_days": len(active_days),
            "behavioral_windows": windows_by_user.get(user_id, 0),
        }
    return per_user


def _event_coverage(events: list[dict]) -> dict:
    coverage = {}
    for category in KNOWN_CATEGORIES:
        matching = [e for e in events if e.get("event_category") == category]
        event_ids = sorted({e["event_id"] for e in matching if e.get("event_id") is not None})
        coverage[category] = {
            "event_count": len(matching),
            "event_ids_seen": event_ids,
            "has_sufficient_data": len(matching) >= MIN_EVENTS_PER_CATEGORY_FOR_ANALYSIS,
        }
    uncategorized = [
        e for e in events if not e.get("event_category") or e.get("event_category") == "uncategorized"
    ]
    coverage["uncategorized"] = {
        "event_count": len(uncategorized),
        "event_ids_seen": sorted({e["event_id"] for e in uncategorized if e.get("event_id") is not None}),
    }
    return coverage


def _feature_coverage(feature_records: list[dict], window_size: str) -> dict:
    same_window = [r for r in feature_records if r.get("window_size") == window_size]
    by_user: dict[str, list[dict]] = {}
    for r in same_window:
        by_user.setdefault(r["user_id"], []).append(r)

    baselines_by_user = {user_id: compute_user_baselines(recs) for user_id, recs in by_user.items()}

    coverage = {}
    for feature_name in REPRESENTATIVE_FEATURES:
        populated_anywhere = any(r.get(feature_name) is not None for r in same_window)
        users_with_enough_history = [
            user_id
            for user_id, baseline in baselines_by_user.items()
            if not baseline.get("insufficient_data")
            and not baseline.get("stats", {}).get(feature_name, {}).get("insufficient_data", True)
        ]
        coverage[feature_name] = {
            "populated_in_any_window": populated_anywhere,
            "users_with_enough_history": users_with_enough_history,
        }
    return coverage


def _human_candidate_users(user_coverage: dict) -> list[str]:
    return [
        user_id
        for user_id, info in user_coverage.items()
        if info.get("account_type") in HUMAN_CANDIDATE_ACCOUNT_TYPES
    ]


def generate_collection_status(
    events: list[dict], feature_records: list[dict], window_size: str = "daily"
) -> dict:
    quality_report = generate_data_quality_report(events, feature_records)
    user_coverage = _user_coverage(events, feature_records, window_size)
    event_coverage = _event_coverage(events)
    feature_coverage = _feature_coverage(feature_records, window_size)
    human_candidates = _human_candidate_users(user_coverage)

    # -- technical sufficiency: does the pipeline actually work end-to-end? --
    technical_reasons = []
    if len(events) == 0:
        technical_reasons.append("No events stored — nothing has been collected yet.")
    if len(feature_records) == 0:
        technical_reasons.append("No behavior_features rows exist — run feature_engineering.py first.")
    technical_sufficiency = len(events) > 0 and len(feature_records) > 0

    # -- research sufficiency: enough real, multi-day human history? --
    research_reasons = []
    qualifying_users = [
        user_id
        for user_id in human_candidates
        if user_coverage[user_id]["events_count"] >= MIN_EVENTS_PER_USER_FOR_ANALYSIS
        and user_coverage[user_id]["behavioral_windows"] >= MIN_WINDOWS_PER_USER_FOR_BASELINE
        and user_coverage[user_id]["active_days"] >= MIN_ACTIVE_DAYS_FOR_RESEARCH
    ]
    categorized_event_count = sum(v["event_count"] for k, v in event_coverage.items() if k in KNOWN_CATEGORIES)

    if not human_candidates:
        research_reasons.append(
            "No user in the database is currently identifiable as a human account "
            "(account_type == 'human_or_unknown') — all stored events are attributable "
            "only to system/service/computer accounts or are unattributed."
        )
    if categorized_event_count < MIN_TOTAL_EVENTS_FOR_ANALYSIS:
        research_reasons.append(
            f"Only {categorized_event_count} categorized (non-uncategorized) real event(s) "
            f"stored — below the {MIN_TOTAL_EVENTS_FOR_ANALYSIS}-event research floor."
        )
    if not qualifying_users:
        research_reasons.append(
            f"No human-candidate user has >= {MIN_EVENTS_PER_USER_FOR_ANALYSIS} events, "
            f">= {MIN_WINDOWS_PER_USER_FOR_BASELINE} behavioral windows, AND "
            f">= {MIN_ACTIVE_DAYS_FOR_RESEARCH} active days of real history all at once — "
            "a meaningful per-user baseline needs all three."
        )
    research_sufficiency = bool(human_candidates) and categorized_event_count >= MIN_TOTAL_EVENTS_FOR_ANALYSIS and bool(qualifying_users)

    decision = "READY_FOR_ML" if (technical_sufficiency and research_sufficiency) else "INSUFFICIENT_REAL_DATA"

    return {
        "decision": decision,
        "technical_sufficiency": {
            "is_sufficient": technical_sufficiency,
            "reasons": technical_reasons,
        },
        "research_sufficiency": {
            "is_sufficient": research_sufficiency,
            "qualifying_users": qualifying_users,
            "reasons": research_reasons,
        },
        "basic_inspection": {
            "total_events": quality_report["total_events"],
            "distinct_event_ids": sorted(
                {e["event_id"] for e in events if e.get("event_id") is not None}
            ),
            "distinct_users": quality_report["distinct_users"],
            "distinct_computers": sorted({e["computer_name"] for e in events if e.get("computer_name")}),
            "coverage_period": quality_report["coverage_period"],
            "total_feature_windows": quality_report["total_feature_windows"],
        },
        "user_coverage": user_coverage,
        "event_coverage": event_coverage,
        "feature_coverage": feature_coverage,
        "thresholds_used": {
            **quality_report["thresholds_used"],
            "min_events_per_category_for_analysis": MIN_EVENTS_PER_CATEGORY_FOR_ANALYSIS,
            "min_active_days_for_research": MIN_ACTIVE_DAYS_FOR_RESEARCH,
            "min_windows_for_baseline": MIN_WINDOWS_FOR_BASELINE,
        },
        "warnings": quality_report["warnings"],
    }
