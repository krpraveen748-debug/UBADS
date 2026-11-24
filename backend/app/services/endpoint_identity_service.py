"""
Service layer for endpoint identity (enrollment/registration/heartbeat) —
the foundation described in Phase 9, extended in Phase 11 with per-agent
credentials. Not a full fleet-management system.
Uses backend's OWN database session (app/db/database.py), not
log-collector's — see app/models/endpoint.py for why.

Enrollment rules (Phase 11), with only the shared enrollment key:
  - no endpoint_id, or an endpoint_id that doesn't exist yet
        -> create the endpoint, issue a new credential (returned once).
  - endpoint_id of a LEGACY record (pre-Phase-11, no credential yet)
        -> one-time enrollment: issue its first credential. Transitional,
           so the endpoint registered during Phase 10 keeps its identity.
  - endpoint_id of an endpoint that already HAS a credential
        -> 409. The enrollment key can never overwrite or re-key an
           enrolled endpoint (this is what stops "change ENDPOINT_ID to
           take over another machine"). Recovery is an explicit local
           operator action: backend/manage_endpoints.py --revoke-credential.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.endpoint import EndpointRecord
from app.security.agent_auth import generate_agent_credential, hash_agent_credential
from app.services import audit_service

logger = logging.getLogger(__name__)

REVOKED_STATUS = "revoked"


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def connection_status(record: EndpointRecord, now: datetime | None = None) -> str:
    """not_enrolled | online | stale | offline — derived from last_seen
    (updated by heartbeat, metadata refresh and ingestion), never stored."""
    if record.credential_hash is None:
        return "not_enrolled"
    if record.last_seen is None:
        return "offline"
    seen = record.last_seen if record.last_seen.tzinfo else record.last_seen.replace(tzinfo=timezone.utc)
    age = ((now or datetime.now(timezone.utc)) - seen).total_seconds()
    if age <= settings.agent_online_within_seconds:
        return "online"
    if age <= settings.agent_stale_after_seconds:
        return "stale"
    return "offline"


def _to_identity_dict(record: EndpointRecord) -> dict:
    """Safe, public fields only — never credential_hash."""
    return {
        "endpoint_id": record.endpoint_id,
        "display_name": record.display_name,
        "operating_system": record.operating_system,
        "agent_version": record.agent_version,
        "status": record.status,
        "registered_at": _iso(record.registered_at),
        "last_seen": _iso(record.last_seen),
        "credential_enrolled": record.credential_hash is not None,
        "credential_issued_at": _iso(record.credential_issued_at),
        "last_ingest_at": _iso(record.last_ingest_at),
        "connection_status": connection_status(record),
        "monitoring_scope": [s for s in (record.monitoring_scope or "").split(",") if s] or None,
    }


def _issue_credential(record: EndpointRecord, now: datetime) -> str:
    credential = generate_agent_credential()
    record.credential_hash = hash_agent_credential(credential)
    record.credential_issued_at = now
    return credential


def enroll_endpoint(
    session: Session,
    *,
    endpoint_id: str | None,
    display_name: str | None,
    operating_system: str | None,
    agent_version: str | None,
) -> dict:
    """Called only after the enrollment key was verified. Returns the
    identity plus `agent_credential` (the ONLY time it is ever returned)."""
    now = datetime.now(timezone.utc)
    resolved_id = endpoint_id or str(uuid.uuid4())

    record = session.get(EndpointRecord, resolved_id)
    if record is not None and (record.status == REVOKED_STATUS or record.enrolled_request_id is not None):
        # A revoked endpoint, or one that belongs to an approved request, is NEVER re-enrolled with
        # the shared key: that would silently undo a revocation (or bypass the request workflow).
        # Revoked endpoints also have no credential, so without this check they looked exactly like
        # a never-enrolled pre-Phase-11 record.
        audit_service.record(
            session, actor="shared-key", action="enrollment.legacy_reenroll_blocked", target=resolved_id,
            request_id=record.enrolled_request_id, detail=f"status={record.status}",
        )
        session.commit()
        logger.warning("Refused shared-key enrollment for revoked or request-linked endpoint %s", resolved_id)
        raise HTTPException(
            status_code=403,
            detail=(
                "This endpoint was revoked or belongs to an approved request, so it cannot be enrolled with the "
                "shared enrollment key. Request access through the UBADS portal."
            ),
        )
    if record is not None and record.credential_hash is not None:
        logger.warning("Refused enrollment for already-enrolled endpoint %s", resolved_id)
        raise HTTPException(
            status_code=409,
            detail=(
                "This endpoint_id is already enrolled with its own credential. "
                "Authenticate with that credential, or have an operator revoke it first."
            ),
        )

    if record is None:
        record = EndpointRecord(
            endpoint_id=resolved_id,
            display_name=display_name,
            operating_system=operating_system,
            agent_version=agent_version,
            status="registered",
            registered_at=now,
            last_seen=now,
        )
        session.add(record)
        logger.info("Enrolled new endpoint %s", resolved_id)
    else:
        record.display_name = display_name or record.display_name
        record.operating_system = operating_system or record.operating_system
        record.agent_version = agent_version or record.agent_version
        record.status = "registered"
        record.last_seen = now
        logger.warning("Enrolled legacy (pre-Phase-11) endpoint %s — first per-agent credential issued", resolved_id)

    credential = _issue_credential(record, now)
    session.commit()
    session.refresh(record)
    return {**_to_identity_dict(record), "agent_credential": credential}


def create_enrolled_endpoint(
    session: Session,
    *,
    endpoint_id: str | None,
    display_name: str | None,
    operating_system: str | None,
    agent_version: str | None,
    monitoring_scope: str,
    request_id: str,
) -> tuple[EndpointRecord, str]:
    """Creates a NEW endpoint for an approved request (Stage 4 redemption) and
    issues its credential. Does not commit - the caller owns the transaction.
    Never reuses or overwrites an existing endpoint id (no takeover)."""
    now = datetime.now(timezone.utc)
    resolved_id = endpoint_id or str(uuid.uuid4())
    if session.get(EndpointRecord, resolved_id) is not None:
        raise HTTPException(status_code=409, detail="endpoint_id already registered.")
    record = EndpointRecord(
        endpoint_id=resolved_id,
        display_name=display_name,
        operating_system=operating_system,
        agent_version=agent_version,
        status="registered",
        registered_at=now,
        last_seen=now,
        monitoring_scope=monitoring_scope,
        enrolled_request_id=request_id,
    )
    credential = _issue_credential(record, now)
    session.add(record)
    return record, credential


def update_registration(
    session: Session,
    record: EndpointRecord,
    *,
    display_name: str | None,
    operating_system: str | None,
    agent_version: str | None,
) -> dict:
    """Metadata refresh for an ALREADY-AUTHENTICATED endpoint. Never issues
    or changes a credential."""
    record.display_name = display_name or record.display_name
    record.operating_system = operating_system or record.operating_system
    record.agent_version = agent_version or record.agent_version
    record.last_seen = datetime.now(timezone.utc)
    session.commit()
    session.refresh(record)
    logger.info("Re-registered authenticated endpoint %s", record.endpoint_id)
    return {**_to_identity_dict(record), "agent_credential": None}


def record_heartbeat(session: Session, record: EndpointRecord) -> dict:
    record.last_seen = datetime.now(timezone.utc)
    record.status = "active"
    session.commit()
    session.refresh(record)
    logger.info("Heartbeat received from endpoint %s", record.endpoint_id)
    return _to_identity_dict(record)


def record_ingest(session: Session, record: EndpointRecord) -> None:
    now = datetime.now(timezone.utc)
    record.last_seen = now
    record.last_ingest_at = now
    session.commit()


def list_endpoints(session: Session) -> list[dict]:
    return [_to_identity_dict(r) for r in session.query(EndpointRecord).order_by(EndpointRecord.registered_at).all()]


def revoke_credential(session: Session, endpoint_id: str) -> bool:
    """Operator action (backend/manage_endpoints.py): clears the stored verifier so the old
    credential stops working immediately and marks the endpoint REVOKED - a final state: the
    shared enrollment key cannot re-enroll it. A non-request-linked endpoint can be allowed back in
    only by the explicit reinstate_endpoint() operator action. Returns False if unknown."""
    record = session.get(EndpointRecord, endpoint_id)
    if record is None:
        return False
    record.credential_hash = None
    record.credential_issued_at = None
    record.status = REVOKED_STATUS
    audit_service.record(session, actor="operator", action="endpoint.credential_revoked", target=endpoint_id)
    session.commit()
    logger.warning("Credential revoked for endpoint %s", endpoint_id)
    return True


def reinstate_endpoint(session: Session, endpoint_id: str) -> str:
    """Operator action: lets a REVOKED endpoint be enrolled again with the shared key. Refused for
    an endpoint that belongs to an approved request (those must go through a new request).
    Returns "reinstated", "unknown", "not_revoked" or "request_linked"."""
    record = session.get(EndpointRecord, endpoint_id)
    if record is None:
        return "unknown"
    if record.enrolled_request_id is not None:
        return "request_linked"
    if record.status != REVOKED_STATUS:
        return "not_revoked"
    record.status = "registered"
    audit_service.record(session, actor="operator", action="endpoint.reinstated", target=endpoint_id)
    session.commit()
    logger.warning("Endpoint %s reinstated for re-enrollment", endpoint_id)
    return "reinstated"
