"""
GET /api/users, GET /api/users/baselines

See backend/app/services/{users_service,baselines_service}.py for the
actual logic.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.repositories.pipeline_bridge import get_session
from app.schemas.users import UserBaseline, UserSummary
from app.services import baselines_service, users_service

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=list[UserSummary])
def list_users(session: Session = Depends(get_session)):
    return users_service.list_human_users(session)


@router.get("/baselines", response_model=list[UserBaseline])
def list_baselines(
    window_size: str = Query("daily", pattern="^(hourly|daily)$"),
    session: Session = Depends(get_session),
):
    return baselines_service.list_user_baselines(session, window_size=window_size)
