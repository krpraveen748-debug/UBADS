"""In-app notifications (no email system exists). Every query is scoped to the
signed-in user's own username: there is no way to read or mark another
user's notification, and a foreign id is indistinguishable from a missing one."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.dashboard_auth import DashboardUser
from app.models.enrollment import Notification


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _out(n: Notification) -> dict:
    return {
        "id": n.id,
        "kind": n.kind,
        "title": n.title,
        "message": n.message,
        "request_id": n.request_id,
        "created_at": _iso(n.created_at),
        "read_at": _iso(n.read_at),
        "read": n.read_at is not None,
    }


def list_notifications(session: Session, user: DashboardUser, *, unread_only: bool, limit: int, offset: int) -> list[dict]:
    query = session.query(Notification).filter(Notification.username == user.username)
    if unread_only:
        query = query.filter(Notification.read_at.is_(None))
    rows = query.order_by(Notification.created_at.desc(), Notification.id.desc()).offset(offset).limit(limit).all()
    return [_out(n) for n in rows]


def unread_count(session: Session, user: DashboardUser) -> int:
    return session.query(Notification).filter(Notification.username == user.username, Notification.read_at.is_(None)).count()


def mark_read(session: Session, user: DashboardUser, notification_id: int) -> dict:
    n = session.get(Notification, notification_id)
    if n is None or n.username != user.username:
        raise HTTPException(status_code=404, detail="Notification not found.")
    if n.read_at is None:
        n.read_at = datetime.now(timezone.utc)
        session.commit()
    return _out(n)


def mark_all_read(session: Session, user: DashboardUser) -> int:
    marked = (
        session.query(Notification)
        .filter(Notification.username == user.username, Notification.read_at.is_(None))
        .update({"read_at": datetime.now(timezone.utc)}, synchronize_session=False)
    )
    session.commit()
    return marked
