"""
GET /api/events, GET /api/events/{id}

See backend/app/services/events_service.py for the actual logic — this
module only defines the HTTP surface (query params, response models,
status codes).
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.repositories.pipeline_bridge import get_session
from app.schemas.events import EventDetail, EventSummary
from app.services import events_service

router = APIRouter(prefix="/api/events", tags=["events"])

_SUMMARY_FIELDS = (
    "id",
    "username",
    "computer_name",
    "event_category",
    "event_id",
    "log_name",
    "account_type",
    "event_type",
    "endpoint_id",
)
_DETAIL_EXTRA_FIELDS = (
    "domain",
    "logon_type",
    "logon_type_description",
    "source_ip",
    "source_machine",
    "failure_reason",
    "file_path",
    "file_extension",
    "file_action",
    "process_name",
    "process_id",
    "parent_process_id",
    "parent_process_name",
    "device_id",
    "device_description",
    "device_class",
    "device_action",
)


def _to_summary(d: dict) -> dict:
    result = {field: d.get(field) for field in _SUMMARY_FIELDS}
    result["timestamp"] = d.get("timestamp_utc")
    return result


def _to_detail(d: dict) -> dict:
    result = _to_summary(d)
    result.update({field: d.get(field) for field in _DETAIL_EXTRA_FIELDS})
    return result


@router.get("", response_model=list[EventSummary])
def list_events(
    limit: int = Query(50, ge=1, le=500, description="Max rows to return."),
    offset: int = Query(0, ge=0),
    category: str | None = Query(None, description="authentication | file_activity | process_activity | device_activity | download_related"),
    username: str | None = None,
    event_id: int | None = Query(None, description="Windows event ID, e.g. 4624."),
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    endpoint_id: str | None = Query(None, description="Restrict to one enrolled endpoint's events."),
    session: Session = Depends(get_session),
):
    rows, _total = events_service.list_events(
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
    return [_to_summary(r) for r in rows]


@router.get("/{event_pk}", response_model=EventDetail)
def get_event(event_pk: int, session: Session = Depends(get_session)):
    record = events_service.get_event(session, event_pk)
    return _to_detail(record)
