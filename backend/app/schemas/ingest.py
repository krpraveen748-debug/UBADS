"""
Request/response models for POST /api/ingest/events.

`events` is a list of already-normalized event dicts — the exact shape
`log-collector/event_parser.normalize_event()` produces (the same shape
`storage.insert_event()` already accepts locally). This route does not
define a new event schema; it accepts the existing one over HTTP.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class IngestEventsRequest(BaseModel):
    log_name: str = "Security"
    events: list[dict[str, Any]]
    # Optional. If sent it must equal the authenticated endpoint (else 403);
    # events are always attributed to the authenticated endpoint regardless.
    endpoint_id: str | None = None


class IngestValidationError(BaseModel):
    event_id: int | None = None
    errors: list[str]


class IngestEventsResponse(BaseModel):
    endpoint_id: str
    accepted: int
    duplicates: int
    validation_errors: int
    out_of_scope: int = 0  # events dropped because they are outside the endpoint's approved scope
    errors: list[IngestValidationError]
