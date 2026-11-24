"""
Response models for /api/events. Deliberately exclude columns that would
expose more than the normalized security/activity metadata UBADS needs:
`raw_event_data` (the full raw Windows payload), `access_list_raw` (a raw
Windows internal string), `user_sid` (an identifier the rest of this
project already avoids surfacing unnecessarily — see
ml-service/user_classification_diagnostics.py), and internal bookkeeping
columns (`event_uid`, `collection_timestamp`).
"""

from __future__ import annotations

from pydantic import BaseModel


class EventSummary(BaseModel):
    """One row in the GET /api/events list — matches the columns the
    frontend's Events page table actually displays."""

    id: int
    timestamp: str | None = None
    username: str | None = None
    computer_name: str | None = None
    event_category: str | None = None
    event_id: int
    log_name: str | None = None
    account_type: str | None = None
    event_type: str | None = None
    # Phase 14 — which enrolled endpoint submitted this event (NULL for
    # events collected before Phase 11, or via the local collector.py CLI
    # directly rather than the agent). Lets the dashboard show multiple
    # endpoints' events without mixing them together.
    endpoint_id: str | None = None


class EventDetail(EventSummary):
    """GET /api/events/{id} — the summary fields plus the rest of the
    normalized (non-raw) metadata for that single event."""

    domain: str | None = None
    logon_type: int | None = None
    logon_type_description: str | None = None
    source_ip: str | None = None
    source_machine: str | None = None
    failure_reason: str | None = None
    file_path: str | None = None
    file_extension: str | None = None
    file_action: str | None = None
    process_name: str | None = None
    process_id: str | None = None
    parent_process_id: str | None = None
    parent_process_name: str | None = None
    device_id: str | None = None
    device_description: str | None = None
    device_class: str | None = None
    device_action: str | None = None
