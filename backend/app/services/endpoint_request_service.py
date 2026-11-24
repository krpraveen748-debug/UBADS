"""User-side endpoint request logic (Phase 17 stage 1).

Admin decisions, notifications API and token redemption arrive in later
stages; this module only creates requests and reads a user's OWN requests.
A user can never see another user's request: lookups by id are scoped to the
requesting username and a miss is a plain 404 (no existence leak).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.dashboard_auth import DashboardUser
from app.models.endpoint import EndpointRecord
from app.models.enrollment import (
    ALLOWED_SCOPES,
    STATUS_APPROVED,
    STATUS_PENDING,
    EndpointRequest,
)
from app.schemas.endpoint_requests import EndpointRequestCreate
from app.security import rate_limit
from app.services import audit_service
from app.services.endpoint_identity_service import connection_status


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _split(value: str | None) -> list[str] | None:
    return [s for s in value.split(",") if s] if value else None


def to_out(session: Session, req: EndpointRequest) -> dict:
    endpoint_status = None
    if req.endpoint_id:
        record = session.get(EndpointRecord, req.endpoint_id)
        endpoint_status = connection_status(record) if record else None
    return {
        "id": req.id,
        "status": req.status,
        "username": req.username,
        "organization": req.organization,
        "department": req.department,
        "justification": req.justification,
        "requested_scope": _split(req.requested_scope) or [],
        "approved_scope": _split(req.approved_scope),
        "status_reason": req.status_reason,
        "decided_by": req.decided_by,
        "decided_at": _iso(req.decided_at),
        "approval_expires_at": _iso(req.approval_expires_at),
        "created_at": _iso(req.created_at),
        "endpoint_id": req.endpoint_id,
        "installed_at": _iso(req.installed_at),
        "endpoint_connection_status": endpoint_status,
        "consent_version": req.consent_version,
        "client_hint": json.loads(req.client_hint) if req.client_hint else None,
    }


def create_request(session: Session, user: DashboardUser, body: EndpointRequestCreate) -> dict:
    if not body.consent_acknowledged:
        raise HTTPException(status_code=422, detail="You must acknowledge the monitoring consent notice to submit a request.")

    scope = list(dict.fromkeys(s.strip() for s in body.requested_scope))
    invalid = [s for s in scope if s not in ALLOWED_SCOPES]
    if invalid:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown monitoring scope(s): {', '.join(invalid)}. Allowed: {', '.join(ALLOWED_SCOPES)}.",
        )

    if rate_limit.request_creations.is_limited(user.username, settings.request_create_max_per_hour, 3600):
        raise HTTPException(
            status_code=429,
            detail="You are submitting requests too quickly. Try again later.",
            headers={"Retry-After": str(rate_limit.request_creations.retry_after(user.username, 3600))},
        )
    rate_limit.request_creations.hit(user.username, 3600)

    organization = (body.organization or user.organization or "").strip()
    if len(organization) < 2:
        raise HTTPException(status_code=422, detail="Organization is required.")

    open_count = (
        session.query(EndpointRequest)
        .filter(EndpointRequest.username == user.username, EndpointRequest.status.in_([STATUS_PENDING, STATUS_APPROVED]))
        .count()
    )
    if open_count >= settings.max_open_requests_per_user:
        raise HTTPException(
            status_code=429,
            detail=f"You already have {open_count} open requests. Wait for a decision or install an approved one first.",
        )

    now = datetime.now(timezone.utc)
    req = EndpointRequest(
        id=str(uuid.uuid4()),
        username=user.username,
        organization=organization,
        department=(body.department or "").strip() or None,
        justification=(body.justification or "").strip() or None,
        requested_scope=",".join(scope),
        client_hint=json.dumps(body.client_hint.model_dump(exclude_none=True)) if body.client_hint else None,
        consent_version=settings.consent_version,
        consent_acknowledged_at=now,
        status=STATUS_PENDING,
        created_at=now,
        updated_at=now,
    )
    session.add(req)
    audit_service.record(
        session,
        actor=user.username,
        action="request.created",
        request_id=req.id,
        detail=f"scope={req.requested_scope}; consent_version={req.consent_version}",
    )
    audit_service.notify_admins(
        session,
        kind="request.pending",
        title="New endpoint request",
        message=f"{user.username} ({organization}) requested agent access for: {req.requested_scope}.",
        request_id=req.id,
    )
    audit_service.notify(
        session,
        username=user.username,
        kind="request.submitted",
        title="Request submitted",
        message="Your request is pending administrator approval. You will be notified of the decision here.",
        request_id=req.id,
    )
    session.commit()
    return to_out(session, req)


def list_my_requests(session: Session, user: DashboardUser) -> list[dict]:
    rows = (
        session.query(EndpointRequest)
        .filter(EndpointRequest.username == user.username)
        .order_by(EndpointRequest.created_at.desc())
        .all()
    )
    return [to_out(session, r) for r in rows]


def get_my_request(session: Session, user: DashboardUser, request_id: str) -> dict:
    req = session.get(EndpointRequest, request_id)
    if req is None or req.username != user.username:
        raise HTTPException(status_code=404, detail="Request not found.")
    return to_out(session, req)
