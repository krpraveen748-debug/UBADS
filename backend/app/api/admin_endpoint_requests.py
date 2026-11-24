"""Administrator-only routes for endpoint requests, audit history and login
unlock (Phase 17 stage 2). The router-level require_admin dependency guards
every route here; a normal user gets 403, an anonymous caller 401."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.dashboard_auth import DashboardUser
from app.security import dashboard_auth
from app.security.dashboard_auth import require_admin
from app.services import admin_request_service as svc
from app.services import audit_service

router = APIRouter(prefix="/api/admin", tags=["admin"], dependencies=[Depends(require_admin)])


class ApproveBody(BaseModel):
    approved_scope: list[str] | None = None  # defaults to the full requested scope
    note: str | None = Field(default=None, max_length=500)


class RejectBody(BaseModel):
    reason: str = Field(min_length=3, max_length=500)

    @field_validator("reason")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if len(v.strip()) < 3:
            raise ValueError("A rejection reason is required.")
        return v.strip()


class RevokeBody(BaseModel):
    reason: str | None = Field(default=None, max_length=500)


class UnlockBody(BaseModel):
    username: str


@router.get("/endpoint-requests")
def list_requests(
    status: str | None = None,
    q: str | None = Query(None, max_length=100, description="Match requester username/name/email or organization."),
    organization: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db),
):
    return svc.list_requests(session, status=status, q=q, organization=organization, limit=limit, offset=offset)


@router.get("/endpoint-requests/{request_id}")
def get_request(request_id: str, session: Session = Depends(get_db)):
    return svc.get_request(session, request_id)


@router.post("/endpoint-requests/{request_id}/approve")
def approve(request_id: str, body: ApproveBody | None = None, admin: DashboardUser = Depends(require_admin), session: Session = Depends(get_db)):
    body = body or ApproveBody()
    return svc.approve(session, admin, request_id, approved_scope=body.approved_scope, note=body.note)


@router.post("/endpoint-requests/{request_id}/reject")
def reject(request_id: str, body: RejectBody, admin: DashboardUser = Depends(require_admin), session: Session = Depends(get_db)):
    return svc.reject(session, admin, request_id, reason=body.reason)


@router.post("/endpoint-requests/{request_id}/revoke")
def revoke(request_id: str, body: RevokeBody | None = None, admin: DashboardUser = Depends(require_admin), session: Session = Depends(get_db)):
    return svc.revoke(session, admin, request_id, reason=(body.reason if body else None))


@router.get("/audit")
def audit(request_id: str | None = None, limit: int = Query(100, ge=1, le=500), session: Session = Depends(get_db)):
    return svc.audit_history(session, request_id=request_id, limit=limit)


@router.post("/auth/unlock")
def unlock(body: UnlockBody, admin: DashboardUser = Depends(require_admin), session: Session = Depends(get_db)):
    """Recovery from a login throttle: clears the failure counters for a username.
    It changes no password and no session, so it cannot take over an account."""
    cleared = dashboard_auth.unlock_username(body.username)
    audit_service.record(session, actor=admin.username, action="auth.unlock", target=body.username.strip().lower(), detail=f"counters_cleared={cleared}")
    session.commit()
    return {"status": "unlocked", "counters_cleared": cleared}
