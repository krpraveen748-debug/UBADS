"""
Phase 17 — user-requested endpoint enrollment.

Four additive tables (no existing table is altered by this module):

- EndpointRequest      what a user asked for + the admin decision. Its
                       `status` is the REQUEST lifecycle only; whether an
                       installed endpoint is online is derived separately
                       from endpoints.last_seen (connection_status).
- EnrollmentAuthorization  a single-use, expiring right to enroll ONE
                       endpoint for ONE approved request. Only a SHA-256 of
                       the token is stored; the raw token is shown once.
- Notification         in-app notifications (no email system exists).
- AuditEvent           append-only record of security-relevant actions.
                       `detail` never contains tokens or credentials.

There is no organizations table in this project, so `organization` is a
validated text field on the user and the request.
"""

from __future__ import annotations

from sqlalchemy import Column, DateTime, Integer, String, Text

from app.db.database import Base

# Request lifecycle statuses (spec section 2).
STATUS_PENDING = "PENDING"
STATUS_APPROVED = "APPROVED"
STATUS_REJECTED = "REJECTED"
STATUS_EXPIRED = "EXPIRED"
STATUS_REVOKED = "REVOKED"
STATUS_ENROLLMENT_PENDING = "ENROLLMENT_PENDING"  # installer package issued, agent has not enrolled yet
STATUS_ENROLLED = "ENROLLED"  # an agent redeemed the one-time code (Stage 3 called this INSTALLED)
REQUEST_STATUSES = (
    STATUS_PENDING,
    STATUS_APPROVED,
    STATUS_REJECTED,
    STATUS_EXPIRED,
    STATUS_REVOKED,
    STATUS_ENROLLMENT_PENDING,
    STATUS_ENROLLED,
)

# Monitoring scopes = the log-collector event categories. Enforced again on
# ingestion in a later stage.
ALLOWED_SCOPES = ("authentication", "file_activity", "process_activity", "device_activity")


class EndpointRequest(Base):
    __tablename__ = "endpoint_requests"

    id = Column(String, primary_key=True)  # uuid4
    username = Column(String, nullable=False, index=True)  # requester
    organization = Column(String, nullable=False)
    department = Column(String, nullable=True)
    justification = Column(Text, nullable=True)
    requested_scope = Column(String, nullable=False)  # comma-separated ALLOWED_SCOPES
    # Browser-side compatibility hint. UNVERIFIED by design: the authoritative
    # computer name/OS comes from the agent at install time.
    client_hint = Column(Text, nullable=True)
    consent_version = Column(String, nullable=False)
    consent_acknowledged_at = Column(DateTime(timezone=True), nullable=False)

    status = Column(String, nullable=False, default=STATUS_PENDING, index=True)
    status_reason = Column(Text, nullable=True)
    decided_by = Column(String, nullable=True)
    decided_at = Column(DateTime(timezone=True), nullable=True)
    approved_scope = Column(String, nullable=True)  # may be narrower than requested
    approval_expires_at = Column(DateTime(timezone=True), nullable=True)

    endpoint_id = Column(String, nullable=True)  # set when the agent redeems
    installed_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)


class EnrollmentAuthorization(Base):
    __tablename__ = "enrollment_authorizations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String, nullable=False, index=True)
    username = Column(String, nullable=False)
    organization = Column(String, nullable=False)
    scope = Column(String, nullable=False)
    token_hash = Column(String, nullable=False, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    redeemed_at = Column(DateTime(timezone=True), nullable=True)
    redeemed_endpoint_id = Column(String, nullable=True)
    superseded_at = Column(DateTime(timezone=True), nullable=True)
    # Phase 17 stage 4
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    redeemed_from_ip = Column(String, nullable=True)


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, nullable=False, index=True)
    kind = Column(String, nullable=False)
    title = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    request_id = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    read_at = Column(DateTime(timezone=True), nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    at = Column(DateTime(timezone=True), nullable=False, index=True)
    actor = Column(String, nullable=True)  # username, "agent", or "system"
    action = Column(String, nullable=False, index=True)
    request_id = Column(String, nullable=True, index=True)
    target = Column(String, nullable=True)
    detail = Column(Text, nullable=True)


