"""
Service layer for /api/events — thin wrapper around log-collector's
storage.query_events()/get_event_by_id()/event_record_to_dict(). Contains
no SQL and no filtering logic of its own; all of that lives in storage.py
(the single repository), as established since Phase 3.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.repositories.pipeline_bridge import storage


def list_events(
    session: Session,
    *,
    limit: int,
    offset: int,
    category: str | None,
    username: str | None,
    event_id: int | None,
    start_time: datetime | None,
    end_time: datetime | None,
    endpoint_id: str | None = None,
) -> tuple[list[dict], int]:
    try:
        rows, total = storage.query_events(
            session,
            limit=limit,
            offset=offset,
            category=category,
            username=username,
            event_id=event_id,
            start_time=start_time,
            end_time=end_time,
            endpoint_id=endpoint_id,
        )
    except Exception as exc:  # pragma: no cover - only on genuine storage failure
        raise HTTPException(status_code=503, detail=f"Event storage unavailable: {exc}") from exc
    return [storage.event_record_to_dict(r) for r in rows], total


def get_event(session: Session, record_id: int) -> dict:
    try:
        record = storage.get_event_by_id(session, record_id)
    except Exception as exc:  # pragma: no cover - only on genuine storage failure
        raise HTTPException(status_code=503, detail=f"Event storage unavailable: {exc}") from exc
    if record is None:
        raise HTTPException(status_code=404, detail=f"Event {record_id} not found")
    return storage.event_record_to_dict(record)
