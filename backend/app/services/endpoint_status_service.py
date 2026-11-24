"""
Service layer for /api/endpoints/status.

There is no persistent agent/heartbeat mechanism in this project yet —
log-collector/collector.py runs as a one-shot CLI script, not a daemon
that reports to the backend. This service therefore never claims a
collector or endpoint is "online" or "running": those fields are always
`None`, and `status` is always "unknown". Every other field is a fact
derived from the real stored event history (or `None` if there is none).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.repositories.pipeline_bridge import storage

RECENT_WINDOW_MINUTES = 5


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def get_endpoint_status(session: Session) -> dict:
    try:
        events = [storage.event_record_to_dict(r) for r in storage.get_all_events(session)]
    except Exception as exc:  # pragma: no cover - only on genuine storage failure
        raise HTTPException(status_code=503, detail=f"Storage unavailable: {exc}") from exc

    base = {
        "endpointName": None,
        "online": None,
        "collectorRunning": None,
        "lastHeartbeat": None,
        "lastEvent": None,
        "eventsPerMinute": None,
        "currentUser": None,
        "categories": [],
        "status": "unknown",
    }
    if not events:
        return base

    timed = [(t, e) for t, e in ((_parse_ts(e.get("timestamp_utc")), e) for e in events) if t is not None]
    if not timed:
        return base
    timed.sort(key=lambda pair: pair[0])
    latest_ts, latest_event = timed[-1]

    recent_cutoff = datetime.now(timezone.utc) - timedelta(minutes=RECENT_WINDOW_MINUTES)
    recent_count = sum(1 for t, _ in timed if t >= recent_cutoff)

    categories = sorted(
        {e["event_category"] for e in events if e.get("event_category") and e["event_category"] != "uncategorized"}
    )

    base.update(
        {
            "endpointName": latest_event.get("computer_name"),
            "lastEvent": latest_ts.isoformat(),
            "eventsPerMinute": round(recent_count / RECENT_WINDOW_MINUTES, 2),
            "currentUser": latest_event.get("username"),
            "categories": categories,
        }
    )
    return base
