"""
POST /api/ingest/events.

Phase 10 implemented the smallest secure ingestion path; every event is
validated and deduplicated using log-collector's existing functions (see
app/services/ingestion_service.py) before ever reaching storage.

Phase 11: authentication is per-agent (X-Endpoint-Id + X-Agent-Credential,
see app/security/agent_auth.py). The shared AGENT_API_KEY is NO LONGER
accepted here — it is an enrollment key only. Every stored event is
attributed to the AUTHENTICATED endpoint; a body-level `endpoint_id` that
differs is rejected (403), and any per-event "endpoint_id" key is ignored.
There is no unauthenticated ingestion path.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.endpoint import EndpointRecord
from app.repositories.pipeline_bridge import get_session
from app.schemas.ingest import IngestEventsRequest, IngestEventsResponse
from app.security.agent_auth import reject_mismatched_endpoint_id, require_authenticated_endpoint
from app.services import anomaly_service, endpoint_identity_service, ingestion_service

router = APIRouter(prefix="/api/ingest", tags=["ingest"])
logger = logging.getLogger(__name__)


@router.post("/events", response_model=IngestEventsResponse)
def ingest_events(
    body: IngestEventsRequest,
    endpoint: EndpointRecord = Depends(require_authenticated_endpoint),
    session: Session = Depends(get_session),
    endpoint_session: Session = Depends(get_db),
):
    reject_mismatched_endpoint_id(body.endpoint_id, endpoint)
    result = ingestion_service.ingest_events(
        session,
        log_name=body.log_name,
        events=body.events,
        endpoint_id=endpoint.endpoint_id,
        monitoring_scope=endpoint.monitoring_scope,
    )
    endpoint_identity_service.record_ingest(endpoint_session, endpoint)
    try:
        anomaly_service.score_endpoint_events(session, endpoint.endpoint_id)
    except Exception:
        session.rollback()
        logger.exception("Anomaly scoring failed after event ingestion for endpoint %s", endpoint.endpoint_id)
    return result
