"""
POST /api/endpoints/register, POST /api/endpoints/heartbeat.

Phase 11 authentication (see app/security/agent_auth.py):
  - register WITH per-agent credential headers (X-Endpoint-Id +
    X-Agent-Credential): metadata refresh for that authenticated endpoint
    only; a different body endpoint_id is rejected (403).
  - register with ONLY the shared enrollment key (X-Agent-Api-Key):
    enrollment of a new (or legacy, not-yet-credentialed) endpoint; issues
    that endpoint's own credential once. Never overwrites an enrolled
    endpoint (409).
  - heartbeat: per-agent credential only. The endpoint updated is always the
    authenticated one, never one named in the body.

These write only endpoint IDENTITY metadata — never security/activity
events (see api/ingest.py for ingestion).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import get_db
from app.models.endpoint import EndpointRecord
from app.schemas.endpoint_identity import (
    EndpointHeartbeatRequest,
    EndpointIdentity,
    EndpointRegisterRequest,
    EndpointRegistrationResponse,
)
from app.security.agent_auth import (
    AGENT_CREDENTIAL_HEADER,
    ENDPOINT_ID_HEADER,
    ENROLLMENT_KEY_HEADER,
    authenticate_endpoint,
    check_enrollment_key,
    reject_mismatched_endpoint_id,
    require_authenticated_endpoint,
)
from app.security.dashboard_auth import require_admin
from app.services import endpoint_identity_service

router = APIRouter(prefix="/api/endpoints", tags=["endpoint-identity"])


@router.get("", response_model=list[EndpointIdentity], dependencies=[Depends(require_admin)])
def list_endpoints(session: Session = Depends(get_db)):
    """Phase 14 — every enrolled/registered endpoint's safe identity
    fields (never a credential or its hash). Lets the frontend populate a
    per-endpoint filter so events from multiple enrolled endpoints can be
    told apart, matching Events API's `endpoint_id` filter. Read-only; requires a
    dashboard session (agent credentials are not accepted here)."""
    return endpoint_identity_service.list_endpoints(session)


@router.post("/register", response_model=EndpointRegistrationResponse)
def register_endpoint(
    body: EndpointRegisterRequest,
    x_agent_api_key: str | None = Header(default=None, alias=ENROLLMENT_KEY_HEADER),
    x_endpoint_id: str | None = Header(default=None, alias=ENDPOINT_ID_HEADER),
    x_agent_credential: str | None = Header(default=None, alias=AGENT_CREDENTIAL_HEADER),
    session: Session = Depends(get_db),
):
    if x_endpoint_id is not None or x_agent_credential is not None:
        # Presenting per-agent credentials means "I am this endpoint" — it
        # must verify; we never silently fall back to the enrollment key.
        record = authenticate_endpoint(session, x_endpoint_id, x_agent_credential)
        reject_mismatched_endpoint_id(body.endpoint_id, record)
        return endpoint_identity_service.update_registration(
            session,
            record,
            display_name=body.display_name,
            operating_system=body.operating_system,
            agent_version=body.agent_version,
        )

    if not settings.legacy_enrollment_allowed:
        # Decided before the key is even looked at, so the answer reveals nothing about the key.
        raise HTTPException(
            status_code=403,
            detail="Shared-key enrollment is disabled on this server. Install the agent with the installer from your UBADS portal.",
        )
    check_enrollment_key(x_agent_api_key)
    return endpoint_identity_service.enroll_endpoint(
        session,
        endpoint_id=body.endpoint_id,
        display_name=body.display_name,
        operating_system=body.operating_system,
        agent_version=body.agent_version,
    )


@router.post("/heartbeat", response_model=EndpointIdentity)
def endpoint_heartbeat(
    body: EndpointHeartbeatRequest | None = None,
    endpoint: EndpointRecord = Depends(require_authenticated_endpoint),
    session: Session = Depends(get_db),
):
    reject_mismatched_endpoint_id(body.endpoint_id if body else None, endpoint)
    return endpoint_identity_service.record_heartbeat(session, endpoint)
