"""GET /api/notifications, /unread-count; POST /{id}/read, /read-all.

Available to any signed-in account, always scoped to THAT account. Admins see
only their own notifications (e.g. "new request"), never a user's."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.dashboard_auth import DashboardUser
from app.security.dashboard_auth import get_current_user
from app.services import notification_service

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


@router.get("")
def list_notifications(
    unread_only: bool = False,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user: DashboardUser = Depends(get_current_user),
    session: Session = Depends(get_db),
):
    return notification_service.list_notifications(session, user, unread_only=unread_only, limit=limit, offset=offset)


@router.get("/unread-count")
def unread_count(user: DashboardUser = Depends(get_current_user), session: Session = Depends(get_db)):
    return {"unread": notification_service.unread_count(session, user)}


@router.post("/read-all")
def read_all(user: DashboardUser = Depends(get_current_user), session: Session = Depends(get_db)):
    return {"marked": notification_service.mark_all_read(session, user)}


@router.post("/{notification_id}/read")
def read_one(notification_id: int, user: DashboardUser = Depends(get_current_user), session: Session = Depends(get_db)):
    return notification_service.mark_read(session, user, notification_id)
