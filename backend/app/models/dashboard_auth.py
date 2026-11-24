"""
Dashboard (human) account tables — entirely separate from the agent
credential model in models/endpoint.py. Only a password HASH and a SHA-256
of each session token are stored; never a password or raw token.

Phase 17: accounts now have a role ("admin" = operator who can see all
telemetry and approve requests; "user" = self-registered requester who can
only see their own endpoint requests) plus profile fields. Existing rows
(pre-Phase-17 operators) are migrated to role "admin" by Alembic.
"""

from __future__ import annotations

from sqlalchemy import Column, DateTime, Integer, String

from app.db.database import Base

ROLE_ADMIN = "admin"
ROLE_USER = "user"


class DashboardUser(Base):
    __tablename__ = "dashboard_users"

    username = Column(String, primary_key=True)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
    # Phase 17
    role = Column(String, nullable=False, default=ROLE_USER, server_default=ROLE_ADMIN)
    email = Column(String, nullable=True)
    full_name = Column(String, nullable=True)
    organization = Column(String, nullable=True)


class DashboardSession(Base):
    __tablename__ = "dashboard_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token_hash = Column(String, nullable=False, unique=True, index=True)
    username = Column(String, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)


