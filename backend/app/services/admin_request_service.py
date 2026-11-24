"""Administrator decisions on endpoint requests (Phase 17 stage 2).

Every decision is:
  - an ATOMIC status transition (conditional UPDATE ... WHERE status IN (...)),
    so two admins racing on one request cannot both win;
  - audited in the same transaction as the change;
  - followed by an in-app notification to the requester.

No enrollment token is generated or redeemed here - that is a later stage.
Revoking an installed request invalidates the endpoint's agent credential
immediately, so its uploads are rejected from then on.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.dashboard_auth import DashboardUser
from app.models.endpoint import EndpointRecord
from app.models.enrollment import (
    ALLOWED_SCOPES,
    REQUEST_STATUSES,
    STATUS_APPROVED,
    STATUS_EXPIRED,
    STATUS_ENROLLED,
    STATUS_ENROLLMENT_PENDING,
    STATUS_PENDING,
    STATUS_REJECTED,
    STATUS_REVOKED,
    AuditEvent,
    EndpointRequest,
    EnrollmentAuthorization,
)
from app.services import audit_service
from app.services.endpoint_request_service import to_out


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _admin_out(session: Session, req: EndpointRequest, *, with_history: bool = False) -> dict:
    out = to_out(session, req)
    requester = session.get(DashboardUser, req.username)
    out["requester_full_name"] = requester.full_name if requester else None
    out["requester_email"] = requester.email if requester else None
    if with_history:
        out["audit_history"] = audit_history(session, request_id=req.id)
    return out


def audit_history(session: Session, *, request_id: str | None = None, limit: int = 200) -> list[dict]:
    query = session.query(AuditEvent)
    if request_id:
        query = query.filter(AuditEvent.request_id == request_id)
    rows = query.order_by(AuditEvent.at.desc(), AuditEvent.id.desc()).limit(limit).all()
    return [
        {"id": r.id, "at": _iso(r.at), "actor": r.actor, "action": r.action, "request_id": r.request_id, "target": r.target, "detail": r.detail}
        for r in rows
    ]


def expire_stale(session: Session) -> int:
    """APPROVED / ENROLLMENT_PENDING requests whose approval window passed become
    EXPIRED (their unredeemed codes are revoked). An ENROLLMENT_PENDING request whose
    last code expired without being used returns to APPROVED so a new package can be
    downloaded."""
    now = datetime.now(timezone.utc)
    expired = 0
    reverted = 0
    for req in session.query(EndpointRequest).filter(EndpointRequest.status == STATUS_ENROLLMENT_PENDING).all():
        window_over = req.approval_expires_at is not None and _aware(req.approval_expires_at) <= now
        if not window_over and session.query(EnrollmentAuthorization).filter(
            EnrollmentAuthorization.request_id == req.id,
            EnrollmentAuthorization.redeemed_at.is_(None),
            EnrollmentAuthorization.superseded_at.is_(None),
            EnrollmentAuthorization.revoked_at.is_(None),
            EnrollmentAuthorization.expires_at > now,
        ).count() == 0:
            if _transition(session, req.id, [STATUS_ENROLLMENT_PENDING], {"status": STATUS_APPROVED, "updated_at": now}):
                audit_service.record(session, actor="system", action="enrollment.code_expired", request_id=req.id, target=req.username)
                reverted += 1
    for req in session.query(EndpointRequest).filter(EndpointRequest.status.in_([STATUS_APPROVED, STATUS_ENROLLMENT_PENDING])).all():
        if req.approval_expires_at is not None and _aware(req.approval_expires_at) <= now:
            if _transition(session, req.id, [STATUS_APPROVED, STATUS_ENROLLMENT_PENDING], {"status": STATUS_EXPIRED, "updated_at": now}):
                session.query(EnrollmentAuthorization).filter(
                    EnrollmentAuthorization.request_id == req.id,
                    EnrollmentAuthorization.redeemed_at.is_(None),
                    EnrollmentAuthorization.revoked_at.is_(None),
                ).update({"revoked_at": now}, synchronize_session=False)
                audit_service.record(session, actor="system", action="request.expired", request_id=req.id, target=req.username)
                audit_service.notify(
                    session,
                    username=req.username,
                    kind="request.expired",
                    title="Approval expired",
                    message="Your approved request expired before the agent was installed. Please submit a new request.",
                    request_id=req.id,
                )
                expired += 1
    if expired or reverted:
        session.commit()
    return expired


def _transition(session: Session, request_id: str, allowed_from: list[str], values: dict) -> bool:
    updated = (
        session.query(EndpointRequest)
        .filter(EndpointRequest.id == request_id, EndpointRequest.status.in_(allowed_from))
        .update(values, synchronize_session=False)
    )
    return updated == 1


def _load(session: Session, request_id: str) -> EndpointRequest:
    req = session.get(EndpointRequest, request_id)
    if req is None:
        raise HTTPException(status_code=404, detail="Request not found.")
    return req


def _conflict(req: EndpointRequest, action: str) -> HTTPException:
    return HTTPException(status_code=409, detail=f"Cannot {action} a request that is {req.status}.")


def _forbid_self_decision(admin: DashboardUser, req: EndpointRequest) -> None:
    if req.username == admin.username and not settings.allow_self_approval:
        raise HTTPException(status_code=403, detail="Administrators cannot approve or reject their own requests.")


def list_requests(
    session: Session, *, status: str | None, q: str | None, organization: str | None, limit: int, offset: int
) -> dict:
    expire_stale(session)
    if status and status not in REQUEST_STATUSES:
        raise HTTPException(status_code=422, detail=f"Unknown status. Allowed: {', '.join(REQUEST_STATUSES)}.")
    query = session.query(EndpointRequest)
    if status:
        query = query.filter(EndpointRequest.status == status)
    if organization:
        query = query.filter(EndpointRequest.organization == organization)
    if q:
        like = f"%{q.strip().lower()}%"
        matching_users = [
            u.username
            for u in session.query(DashboardUser).filter(
                func.lower(DashboardUser.username).like(like)
                | func.lower(func.coalesce(DashboardUser.email, "")).like(like)
                | func.lower(func.coalesce(DashboardUser.full_name, "")).like(like)
            )
        ]
        query = query.filter(
            EndpointRequest.username.in_(matching_users) | func.lower(EndpointRequest.organization).like(like)
        )
    total = query.count()
    rows = query.order_by(EndpointRequest.created_at.desc()).offset(offset).limit(limit).all()
    counts = dict(session.query(EndpointRequest.status, func.count()).group_by(EndpointRequest.status).all())
    return {
        "items": [_admin_out(session, r) for r in rows],
        "total": total,
        "counts": {s: counts.get(s, 0) for s in REQUEST_STATUSES},
    }


def get_request(session: Session, request_id: str) -> dict:
    expire_stale(session)
    return _admin_out(session, _load(session, request_id), with_history=True)


def approve(session: Session, admin: DashboardUser, request_id: str, *, approved_scope: list[str] | None, note: str | None) -> dict:
    req = _load(session, request_id)
    _forbid_self_decision(admin, req)
    requested = req.requested_scope.split(",")
    scope = list(dict.fromkeys(approved_scope)) if approved_scope else requested
    if not scope or any(s not in ALLOWED_SCOPES or s not in requested for s in scope):
        raise HTTPException(status_code=422, detail="Approved scope must be a non-empty subset of the requested scope.")

    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=settings.approval_valid_days)
    if not _transition(
        session,
        request_id,
        [STATUS_PENDING],
        {
            "status": STATUS_APPROVED,
            "decided_by": admin.username,
            "decided_at": now,
            "approved_scope": ",".join(scope),
            "approval_expires_at": expires,
            "status_reason": (note or "").strip() or None,
            "updated_at": now,
        },
    ):
        session.rollback()
        raise _conflict(_load(session, request_id), "approve")
    audit_service.record(
        session,
        actor=admin.username,
        action="request.approved",
        request_id=request_id,
        target=req.username,
        detail=f"approved_scope={','.join(scope)}; requested_scope={req.requested_scope}; valid_until={expires.isoformat()}",
    )
    narrowed = " (narrower than requested)" if set(scope) != set(requested) else ""
    audit_service.notify(
        session,
        username=req.username,
        kind="request.approved",
        title="Request approved",
        message=f"Your endpoint request was approved for: {', '.join(scope)}{narrowed}. "
        f"The approval is valid until {expires.strftime('%Y-%m-%d %H:%M UTC')}.",
        request_id=request_id,
    )
    session.commit()
    session.expire_all()
    return _admin_out(session, _load(session, request_id), with_history=True)


def reject(session: Session, admin: DashboardUser, request_id: str, *, reason: str) -> dict:
    req = _load(session, request_id)
    _forbid_self_decision(admin, req)
    now = datetime.now(timezone.utc)
    if not _transition(
        session,
        request_id,
        [STATUS_PENDING],
        {"status": STATUS_REJECTED, "decided_by": admin.username, "decided_at": now, "status_reason": reason.strip(), "updated_at": now},
    ):
        session.rollback()
        raise _conflict(_load(session, request_id), "reject")
    audit_service.record(session, actor=admin.username, action="request.rejected", request_id=request_id, target=req.username, detail=f"reason={reason.strip()}")
    audit_service.notify(
        session,
        username=req.username,
        kind="request.rejected",
        title="Request rejected",
        message=f"Your endpoint request was rejected. Reason: {reason.strip()}",
        request_id=request_id,
    )
    session.commit()
    session.expire_all()
    return _admin_out(session, _load(session, request_id), with_history=True)


def revoke(session: Session, admin: DashboardUser, request_id: str, *, reason: str | None) -> dict:
    """APPROVED / ENROLLMENT_PENDING -> REVOKED (unredeemed codes are revoked), or
    ENROLLED -> REVOKED, which also invalidates the endpoint's credential (uploads
    then fail with 401)."""
    req = _load(session, request_id)
    now = datetime.now(timezone.utc)
    endpoint_id = req.endpoint_id
    if not _transition(
        session,
        request_id,
        [STATUS_APPROVED, STATUS_ENROLLMENT_PENDING, STATUS_ENROLLED],
        {"status": STATUS_REVOKED, "status_reason": (reason or "").strip() or None, "decided_by": admin.username, "decided_at": now, "updated_at": now},
    ):
        session.rollback()
        raise _conflict(_load(session, request_id), "revoke")

    # No unredeemed code for this request may be used any more.
    codes_revoked = (
        session.query(EnrollmentAuthorization)
        .filter(
            EnrollmentAuthorization.request_id == request_id,
            EnrollmentAuthorization.redeemed_at.is_(None),
            EnrollmentAuthorization.revoked_at.is_(None),
        )
        .update({"revoked_at": now}, synchronize_session=False)
    )

    credential_revoked = False
    if endpoint_id:
        record = session.get(EndpointRecord, endpoint_id)
        if record is not None:
            record.credential_hash = None  # old credential stops working immediately
            record.credential_issued_at = None
            record.status = "revoked"
            credential_revoked = True
    audit_service.record(
        session,
        actor=admin.username,
        action="request.revoked",
        request_id=request_id,
        target=endpoint_id or req.username,
        detail=f"credential_revoked={credential_revoked}; codes_revoked={codes_revoked}; reason={(reason or '').strip() or '-'}",
    )
    audit_service.notify(
        session,
        username=req.username,
        kind="request.revoked",
        title="Access revoked",
        message="An administrator revoked your UBADS agent authorization."
        + (f" Reason: {reason.strip()}" if reason and reason.strip() else ""),
        request_id=request_id,
    )
    session.commit()
    session.expire_all()
    return _admin_out(session, _load(session, request_id), with_history=True)
