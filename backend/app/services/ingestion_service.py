"""
Service layer for POST /api/ingest/events — the smallest secure ingestion
functionality needed for a real Windows agent to submit events (Phase 10).

Contains NO validation or storage logic of its own: every event is
validated with log-collector's validation.validate_event() (the exact
rules log-collector/collector.py already enforces for its own local
pipeline) and stored with storage.insert_event() (the exact same
deduplication-by-event_uid logic). An invalid event is never stored —
it is only counted and its reasons reported back to the caller.

Phase 11: `endpoint_id` is the AUTHENTICATED endpoint (resolved from the
agent's credential by the route, never from the request body). It is
passed to storage.insert_event() so every stored event is attributed to
the endpoint that actually submitted it, and so deduplication keys are
namespaced per endpoint (see storage.build_event_uid).
"""

from __future__ import annotations

import logging

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.repositories.pipeline_bridge import event_parser, storage, validation

logger = logging.getLogger(__name__)


# A category label an agent may attach in addition to the one its event ID implies. The collector
# marks some file events "download_related" (path-based); that is the ONLY legitimate refinement.
_ALLOWED_REFINEMENTS: dict[str, set[str]] = {"file_activity": {"download_related"}}


def allowed_categories(monitoring_scope: str | None) -> set[str] | None:
    """Event categories an endpoint may upload, expressed in the categories that EVENT IDS
    imply (never the agent's label). None = unrestricted (legacy endpoints)."""
    if not monitoring_scope:
        return None
    return {s for s in monitoring_scope.split(",") if s}


def _echo_id(event_id) -> int | None:
    """Only a real integer id is echoed back in a rejection entry; anything else (list, object,
    string...) would make the error response itself invalid and turn a clean rejection into a 500."""
    return event_id if isinstance(event_id, int) and not isinstance(event_id, bool) else None


def classify_event(event: dict) -> tuple[str | None, str | None]:
    """Returns (category, rejection_reason). The category comes ONLY from the Windows event ID
    (the collector's own EVENT_CATEGORY_MAP) - the agent-supplied `event_category` is never the
    authority for authorization. A supplied label must be absent, equal to the derived category,
    or an allowed refinement of it; anything else means a buggy or tampered client and the event
    is rejected. Unknown or unsupported event IDs are rejected."""
    event_id = event.get("event_id")
    derived = event_parser.EVENT_CATEGORY_MAP.get(event_id) if isinstance(event_id, int) and not isinstance(event_id, bool) else None
    if derived is None:
        return None, "unsupported_event_id"
    supplied = event.get("event_category")
    if supplied is None:
        return derived, None
    if not isinstance(supplied, str) or (supplied != derived and supplied not in _ALLOWED_REFINEMENTS.get(derived, set())):
        return None, "event_category_mismatch"
    return derived, None


def ingest_events(
    session: Session, *, log_name: str, events: list[dict], endpoint_id: str, monitoring_scope: str | None = None
) -> dict:
    allowed = allowed_categories(monitoring_scope)
    out_of_scope = 0
    accepted = 0
    duplicates = 0
    validation_errors: list[dict] = []

    for event in events:
        result = validation.validate_event(event)
        if not result.is_valid:
            validation_errors.append({"event_id": _echo_id(event.get("event_id")), "errors": result.errors})
            continue

        category, rejection = classify_event(event)
        if rejection:
            validation_errors.append({"event_id": _echo_id(event.get("event_id")), "errors": [rejection]})
            continue
        if allowed is not None and category not in allowed:
            out_of_scope += 1  # outside the approved monitoring scope: never stored
            continue
        # Store the category the event ID implies (or its allowed refinement), never an unchecked label.
        event = {**event, "event_category": event.get("event_category") or category}

        try:
            outcome = storage.insert_event(session, event, log_name=log_name, endpoint_id=endpoint_id)
        except Exception as exc:  # pragma: no cover - only on genuine storage failure
            logger.exception("Storage failure while ingesting event batch")
            raise HTTPException(status_code=503, detail=f"Event storage unavailable: {exc}") from exc

        if outcome == "inserted":
            accepted += 1
        else:
            duplicates += 1

    if validation_errors:
        logger.warning("Rejected %d invalid event(s) during ingestion", len(validation_errors))
    logger.info(
        "Ingested batch from endpoint %s, log '%s': accepted=%d duplicates=%d validation_errors=%d",
        endpoint_id,
        log_name,
        accepted,
        duplicates,
        len(validation_errors),
    )

    return {
        "endpoint_id": endpoint_id,
        "accepted": accepted,
        "duplicates": duplicates,
        "validation_errors": len(validation_errors),
        "out_of_scope": out_of_scope,
        "errors": validation_errors,
    }
