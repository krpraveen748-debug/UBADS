"""Append-only audit log + in-app notifications for the enrollment workflow.

`detail` must never contain a token, credential or password - callers pass
only ids, statuses and human-readable reasons.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.dashboard_auth import ROLE_ADMIN, DashboardUser
from app.models.enrollment import AuditEvent, Notification

logger = logging.getLogger(__name__)


def record(
    session: Session,
    *,
    actor: str | None,
    action: str,
    request_id: str | None = None,
    target: str | None = None,
    detail: str | None = None,
) -> None:
    """Adds the audit row to the session; the caller commits it together
    with the change it describes (so the log and the change cannot diverge)."""
    session.add(
        AuditEvent(
            at=datetime.now(timezone.utc), actor=actor, action=action, request_id=request_id, target=target, detail=detail
        )
    )
    logger.info("audit action=%s actor=%s request=%s target=%s", action, actor, request_id, target)


def notify(session: Session, *, username: str, kind: str, title: str, message: str, request_id: str | None = None) -> None:
    session.add(
        Notification(
            username=username,
            kind=kind,
            title=title,
            message=message,
            request_id=request_id,
            created_at=datetime.now(timezone.utc),
        )
    )


def notify_admins(session: Session, *, kind: str, title: str, message: str, request_id: str | None = None) -> None:
    for admin in session.query(DashboardUser).filter(DashboardUser.role == ROLE_ADMIN):
        notify(session, username=admin.username, kind=kind, title=title, message=message, request_id=request_id)
