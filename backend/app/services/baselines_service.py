"""
Service layer for /api/users/baselines.

Reuses ml-service's real, already-implemented computations directly:
  - collection_status.generate_collection_status() for per-user event/
    window coverage and which users qualify as research-sufficient.
  - baseline_stats.compute_user_baselines() for the insufficient/building/
    ready determination (same MIN_WINDOWS_FOR_BASELINE rule ml-service's
    own CLI uses).
  - user_identity.resolve_user_id() for grouping, identical to how
    feature_engineering.py groups events.

This module does NOT recompute feature windows (that would mean writing to
behavior_features from a GET request) — it only reads what
feature_engineering.py has already computed and stored. If no feature
windows exist yet for a user, that is reported honestly as
"insufficient_data", never fabricated.

The only genuinely new logic here is presentation-shaping for the
frontend's already-built Users & Baselines page (typical login window,
typical activity hours, common categories) — straightforward aggregation
over real data, not a business rule being duplicated from elsewhere.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.repositories.pipeline_bridge import baseline_stats, collection_status, storage, user_identity

DEFAULT_WINDOW_SIZE = "daily"
HUMAN_ACCOUNT_TYPE = "human_or_unknown"


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _typical_login_window(user_feature_records: list[dict]) -> str:
    hours = [
        (r.get("first_login_hour"), r.get("last_login_hour"))
        for r in user_feature_records
        if r.get("first_login_hour") is not None and r.get("last_login_hour") is not None
    ]
    if not hours:
        return "Insufficient data"
    first = min(h[0] for h in hours)
    last = max(h[1] for h in hours)
    return f"{first:02d}:00–{last:02d}:00"


def _typical_activity_hours(user_events: list[dict]) -> str:
    event_hours = [t.hour for t in (_parse_ts(e.get("timestamp_utc")) for e in user_events) if t is not None]
    if not event_hours:
        return "Insufficient data"
    return f"{min(event_hours):02d}:00–{max(event_hours):02d}:00"


def _common_categories(user_events: list[dict], top_n: int = 4) -> list[str]:
    counts = Counter(
        e["event_category"] for e in user_events if e.get("event_category") and e["event_category"] != "uncategorized"
    )
    return [category for category, _ in counts.most_common(top_n)]


def _baseline_status(baseline: dict) -> str:
    if baseline["window_count"] == 0:
        return "insufficient_data"
    if baseline["insufficient_data"]:
        return "building"
    return "ready"


def list_user_baselines(session: Session, window_size: str = DEFAULT_WINDOW_SIZE) -> list[dict]:
    try:
        events = [storage.event_record_to_dict(r) for r in storage.get_all_events(session)]
        feature_records = [
            storage.feature_record_to_dict(r) for r in storage.get_feature_records(session, limit=100000)
        ]
    except Exception as exc:  # pragma: no cover - only on genuine storage failure
        raise HTTPException(status_code=503, detail=f"Storage unavailable: {exc}") from exc

    status_report = collection_status.generate_collection_status(events, feature_records, window_size=window_size)
    qualifying_users = set(status_report["research_sufficiency"]["qualifying_users"])
    user_coverage = status_report["user_coverage"]

    events_by_user: dict[str, list[dict]] = {}
    for e in events:
        events_by_user.setdefault(user_identity.resolve_user_id(e), []).append(e)

    records_by_user: dict[str, list[dict]] = {}
    for r in feature_records:
        if r.get("window_size") == window_size:
            records_by_user.setdefault(r["user_id"], []).append(r)

    results: list[dict] = []
    for user_id, coverage in user_coverage.items():
        if coverage.get("account_type") != HUMAN_ACCOUNT_TYPE:
            continue

        user_events = events_by_user.get(user_id, [])
        user_records = records_by_user.get(user_id, [])
        baseline = baseline_stats.compute_user_baselines(user_records)

        username = next((r.get("username") for r in user_records if r.get("username")), None)
        if not username:
            username = next((e.get("username") for e in user_events if e.get("username")), None)
        if not username:
            username = user_id

        distinct_computers = coverage.get("distinct_computers") or []

        results.append(
            {
                "username": username,
                "endpoint": distinct_computers[0] if distinct_computers else None,
                "observedDays": coverage.get("active_days", 0),
                "events": coverage.get("events_count", 0),
                "typicalLoginWindow": _typical_login_window(user_records),
                "typicalActivityHours": _typical_activity_hours(user_events),
                "commonCategories": _common_categories(user_events),
                "baselineStatus": _baseline_status(baseline),
                "mlReadiness": "Ready" if user_id in qualifying_users else "Insufficient real data",
            }
        )

    return results
