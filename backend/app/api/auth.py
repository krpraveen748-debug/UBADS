"""POST /api/auth/register, /login, /logout, GET /api/auth/me.

Register creates a normal "user" account only - it can never create an
administrator (those come from backend/manage_dashboard_users.py).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import get_db
from app.models.dashboard_auth import ROLE_USER, DashboardUser
from app.schemas.endpoint_requests import RegisterRequest
from app.security import dashboard_auth, rate_limit
from app.security.client_ip import get_client_ip
from app.services import audit_service

router = APIRouter(prefix="/api/auth", tags=["auth"])

class LoginRequest(BaseModel):
    username: str
    password: str


def _check_register_rate(ip: str) -> None:
    if rate_limit.registrations.is_limited(ip, settings.registration_max_per_hour, 3600):
        raise HTTPException(
            status_code=429,
            detail="Too many registrations from this address. Try again later.",
            headers={"Retry-After": str(rate_limit.registrations.retry_after(ip, 3600))},
        )
    rate_limit.registrations.hit(ip, 3600)  # every attempt counts, successful or not


@router.post("/register", status_code=201)
def register(body: RegisterRequest, request: Request, session: Session = Depends(get_db)):
    if not settings.registration_enabled:
        raise HTTPException(status_code=403, detail="Self-registration is disabled on this server.")
    _check_register_rate(get_client_ip(request))
    taken = session.get(DashboardUser, body.username) is not None
    if taken or session.query(DashboardUser).filter(DashboardUser.email == body.email).first() is not None:
        # One message for "username taken" and "email already registered", so
        # the form does not tell a visitor which of them exists. (Fully hiding
        # account existence would need email verification.)
        raise HTTPException(status_code=409, detail="Registration could not be completed with these details. Try different ones.")
    try:
        dashboard_auth.create_user(
            session,
            body.username,
            body.password,
            role=ROLE_USER,
            email=body.email,
            full_name=body.full_name,
            organization=body.organization,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    audit_service.record(session, actor=body.username, action="user.registered", target=body.username)
    session.commit()
    return {"status": "registered", "username": body.username, "role": ROLE_USER}


@router.post("/login")
def login(body: LoginRequest, request: Request, session: Session = Depends(get_db)):
    return dashboard_auth.login(session, body.username, body.password, get_client_ip(request))


@router.post("/logout")
def logout(
    authorization: str | None = Header(default=None),
    _user: str = Depends(dashboard_auth.require_dashboard_user),
    session: Session = Depends(get_db),
):
    dashboard_auth.revoke_token(session, dashboard_auth.bearer_token(authorization))
    return {"status": "logged_out"}


@router.get("/me")
def me(user: DashboardUser = Depends(dashboard_auth.get_current_user)):
    return {
        "username": user.username,
        "role": user.role,
        "email": user.email,
        "full_name": user.full_name,
        "organization": user.organization,
    }
