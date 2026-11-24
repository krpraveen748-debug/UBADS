"""
One-time endpoint enrollment codes (Phase 17 stage 4). See
docs/phase17-enrollment-security-design.md for the full model.

  mint_package()  - the approved requester asks for an installer package; a fresh
                    single-use code is created (hash only is stored) and returned
                    ONCE; older unredeemed codes for the request are superseded.
  redeem()        - the Windows agent presents the code; everything below happens in
                    ONE transaction and the claim is an atomic conditional UPDATE, so
                    concurrent redemptions produce exactly one credential.

Secrets never appear in logs or audit detail: only request ids, endpoint ids,
outcomes and reasons are recorded.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.dashboard_auth import DashboardUser
from app.models.enrollment import (
    ALLOWED_SCOPES,
    STATUS_APPROVED,
    STATUS_ENROLLED,
    STATUS_ENROLLMENT_PENDING,
    STATUS_REVOKED,
    EndpointRequest,
    EnrollmentAuthorization,
)
from app.security import rate_limit
from app.services import audit_service, endpoint_identity_service

logger = logging.getLogger(__name__)

CODE_PREFIX = "ubads1"
_SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")  # token_urlsafe(32)
_OPEN = (STATUS_APPROVED, STATUS_ENROLLMENT_PENDING)


# ---------------------------------------------------------------- primitives


def hash_secret(secret: str) -> str:
    """Only this digest is ever stored. The secret has 256 bits of entropy, so a
    fast hash is appropriate (same reasoning as agent credentials)."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def build_code(base_url: str, secret: str) -> str:
    hint = base64.urlsafe_b64encode(base_url.encode("utf-8")).decode("ascii").rstrip("=")
    return f"{CODE_PREFIX}.{hint}.{secret}"


@dataclass(frozen=True)
class ParsedCode:
    base_url: str  # a HINT for the agent only; the server never trusts it
    secret: str


def parse_code(code: str | None) -> ParsedCode | None:
    parts = (code or "").strip().split(".")
    if len(parts) != 3 or parts[0] != CODE_PREFIX or not _SECRET_RE.match(parts[2]):
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        base_url = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeError, ValueError):
        return None
    if not base_url.startswith(("http://", "https://")):
        return None
    return ParsedCode(base_url=base_url, secret=parts[2])


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _error(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message})


def active_codes_query(session: Session, request_id: str, now: datetime):
    return session.query(EnrollmentAuthorization).filter(
        EnrollmentAuthorization.request_id == request_id,
        EnrollmentAuthorization.redeemed_at.is_(None),
        EnrollmentAuthorization.superseded_at.is_(None),
        EnrollmentAuthorization.revoked_at.is_(None),
        EnrollmentAuthorization.expires_at > now,
    )


# ---------------------------------------------------------------- minting (4B)

_MINT_DENIAL = {
    "PENDING": "This request is still waiting for administrator approval.",
    "REJECTED": "This request was rejected, so an installer package is not available for it.",
    "REVOKED": "This authorization was revoked, so an installer package is no longer available for it.",
    "EXPIRED": "This approval expired. Please submit a new request.",
    "ENROLLED": "An agent is already enrolled for this request.",
}


@dataclass(frozen=True)
class MintedCode:
    code: str
    expires_at: datetime


def check_mint_rate_limit(user: DashboardUser) -> None:
    if rate_limit.enrollment_mints.is_limited(user.username, settings.enrollment_mint_max_per_hour, 3600):
        raise HTTPException(
            status_code=429,
            detail="You are requesting installer packages too quickly. Try again later.",
            headers={"Retry-After": str(rate_limit.enrollment_mints.retry_after(user.username, 3600))},
        )


def mint_package(session: Session, user: DashboardUser, request_id: str) -> MintedCode:
    """Creates a fresh single-use code for the OWNER of an approved request.
    Calling it again (refresh, second click) supersedes the previous unredeemed
    code - it can never consume an authorization."""
    from app.services.admin_request_service import expire_stale  # local import: avoids a cycle
    from app.services.installer_download_service import installer_info

    base_url = settings.resolved_public_base_url
    if not base_url:
        raise _error(503, "server_not_configured", "Enrollment is not configured on this server (PUBLIC_BASE_URL must be an https:// address in production).")
    if not installer_info()["available"]:
        raise _error(503, "installer_unavailable", "The installer is not available on this server. Contact an administrator.")

    check_mint_rate_limit(user)
    rate_limit.enrollment_mints.hit(user.username, 3600)

    expire_stale(session)
    req = session.get(EndpointRequest, request_id)
    if req is None or req.username != user.username:
        raise HTTPException(status_code=404, detail="Request not found.")
    session.refresh(req)
    if req.status not in _OPEN:
        raise HTTPException(status_code=403, detail=_MINT_DENIAL.get(req.status, "An installer package is not available for this request."))

    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=settings.enrollment_code_ttl_minutes)
    if req.approval_expires_at is not None:
        expires = min(expires, _aware(req.approval_expires_at))
    if expires <= now:
        raise HTTPException(status_code=403, detail=_MINT_DENIAL["EXPIRED"])

    secret = secrets.token_urlsafe(32)
    superseded = (
        session.query(EnrollmentAuthorization)
        .filter(
            EnrollmentAuthorization.request_id == req.id,
            EnrollmentAuthorization.redeemed_at.is_(None),
            EnrollmentAuthorization.superseded_at.is_(None),
            EnrollmentAuthorization.revoked_at.is_(None),
        )
        .update({"superseded_at": now}, synchronize_session=False)
    )
    session.add(
        EnrollmentAuthorization(
            request_id=req.id,
            username=req.username,
            organization=req.organization,
            scope=req.approved_scope or "",
            token_hash=hash_secret(secret),
            created_at=now,
            expires_at=expires,
        )
    )
    moved = (
        session.query(EndpointRequest)
        .filter(EndpointRequest.id == req.id, EndpointRequest.status.in_(_OPEN))
        .update({"status": STATUS_ENROLLMENT_PENDING, "updated_at": now}, synchronize_session=False)
    )
    if moved != 1:  # revoked / decided between the checks above and now
        session.rollback()
        raise HTTPException(status_code=409, detail="This request changed while the package was being prepared. Reload and try again.")
    if superseded:
        audit_service.record(session, actor=user.username, action="enrollment.code_superseded", request_id=req.id, detail=f"previous_codes_superseded={superseded}")
    audit_service.record(
        session,
        actor=user.username,
        action="enrollment.code_issued",
        request_id=req.id,
        target=req.username,
        detail=f"expires_at={expires.isoformat()}; scope={req.approved_scope}",
    )
    session.commit()
    return MintedCode(code=build_code(base_url, secret), expires_at=expires)


# ---------------------------------------------------------------- redemption (4C)


def _fail(session: Session, *, status: int, code: str, message: str, request_id: str | None = None, ip: str | None = None) -> HTTPException:
    session.rollback()
    rate_limit.enrollment_redeem_failures.hit(ip or "unknown", settings.dashboard_login_lockout_seconds)
    audit_service.record(session, actor="agent", action="enrollment.redeem_failed", request_id=request_id, detail=f"reason={code}; ip={ip or 'unknown'}")
    session.commit()
    return _error(status, code, message)


def redeem(session: Session, **kwargs) -> dict:
    """See _redeem. A database that is busy/locked for too long is reported as a safe,
    retryable 503: the transaction is rolled back first, so the code is NOT consumed."""
    try:
        return _redeem(session, **kwargs)
    except OperationalError:
        session.rollback()
        logger.warning("Enrollment redemption hit a database error; rolled back (code not consumed).")
        raise HTTPException(
            status_code=503,
            detail={"code": "server_busy", "message": "The server is busy. Nothing was changed; try again in a moment."},
            headers={"Retry-After": "5"},
        ) from None


def _redeem(
    session: Session,
    *,
    code: str,
    display_name: str | None,
    operating_system: str | None,
    agent_version: str | None,
    endpoint_id: str | None,
    ip: str,
) -> dict:
    window = settings.dashboard_login_lockout_seconds
    if rate_limit.enrollment_redeem_failures.is_limited(ip, settings.enrollment_redeem_max_failures_per_ip, window):
        raise HTTPException(
            status_code=429,
            detail={"code": "rate_limited", "message": "Too many failed enrollment attempts. Try again later."},
            headers={"Retry-After": str(rate_limit.enrollment_redeem_failures.retry_after(ip, window))},
        )

    parsed = parse_code(code)
    auth = None
    if parsed is not None:
        auth = session.query(EnrollmentAuthorization).filter(EnrollmentAuthorization.token_hash == hash_secret(parsed.secret)).first()
    if auth is None:  # malformed and unknown look identical to the caller
        logger.warning("Enrollment redemption rejected: invalid code (ip=%s)", ip)
        rate_limit.enrollment_redeem_failures.hit(ip, window)
        raise _error(401, "invalid_code", "This enrollment code is not valid. Download a fresh installer from the UBADS portal.")

    # From here the caller has proven knowledge of the secret, so specific reasons are safe to give.
    rid = auth.request_id
    now = datetime.now(timezone.utc)
    if auth.revoked_at is not None:
        raise _fail(session, status=403, code="revoked", message="This authorization was revoked by an administrator.", request_id=rid, ip=ip)
    if auth.redeemed_at is not None:
        raise _fail(session, status=409, code="already_used", message="This enrollment code was already used. Download a fresh installer from the UBADS portal.", request_id=rid, ip=ip)
    if auth.superseded_at is not None:
        raise _fail(session, status=410, code="superseded", message="A newer installer was issued for this request. Use the most recently downloaded one.", request_id=rid, ip=ip)
    if _aware(auth.expires_at) <= now:
        raise _fail(session, status=410, code="expired", message="This enrollment code expired. Download a fresh installer from the UBADS portal.", request_id=rid, ip=ip)

    req = session.get(EndpointRequest, rid)
    session.refresh(auth)
    if auth.redeemed_at is not None:
        # Lost a race: another caller consumed this code (and moved the request on) between our
        # first read and now. Report what actually happened, not a side effect of it.
        raise _fail(session, status=409, code="already_used", message="This enrollment code was already used. Download a fresh installer from the UBADS portal.", request_id=rid, ip=ip)
    if req is None or req.username != auth.username or req.organization != auth.organization:
        raise _fail(session, status=403, code="request_mismatch", message="This enrollment code does not match its approved request.", request_id=rid, ip=ip)
    if req.status == STATUS_REVOKED:
        raise _fail(session, status=403, code="revoked", message="This authorization was revoked by an administrator.", request_id=rid, ip=ip)
    if req.status not in _OPEN:
        raise _fail(session, status=403, code="request_not_approved", message=f"This request is {req.status} and cannot enroll an agent.", request_id=rid, ip=ip)
    if req.approval_expires_at is not None and _aware(req.approval_expires_at) <= now:
        raise _fail(session, status=410, code="expired", message="The approval for this request expired. Submit a new request.", request_id=rid, ip=ip)
    if session.get(DashboardUser, auth.username) is None:
        raise _fail(session, status=403, code="account_unavailable", message="The account that owns this request no longer exists.", request_id=rid, ip=ip)

    approved = [s for s in (req.approved_scope or "").split(",") if s]
    requested = set((req.requested_scope or "").split(","))
    pinned = [s for s in (auth.scope or "").split(",") if s]
    if not approved or set(approved) != set(pinned) or not set(approved) <= requested or not set(approved) <= set(ALLOWED_SCOPES):
        raise _fail(session, status=403, code="scope_mismatch", message="The approved monitoring scope does not match this enrollment code.", request_id=rid, ip=ip)

    new_id = endpoint_id
    if new_id is not None:
        try:
            new_id = str(uuid.UUID(str(new_id)))
        except ValueError:
            raise _fail(session, status=422, code="invalid_endpoint_id", message="endpoint_id must be a UUID.", request_id=rid, ip=ip) from None
    else:
        new_id = str(uuid.uuid4())

    # ---- atomic claim: exactly one caller can flip redeemed_at ----
    claimed = (
        session.query(EnrollmentAuthorization)
        .filter(
            EnrollmentAuthorization.id == auth.id,
            EnrollmentAuthorization.redeemed_at.is_(None),
            EnrollmentAuthorization.superseded_at.is_(None),
            EnrollmentAuthorization.revoked_at.is_(None),
            EnrollmentAuthorization.expires_at > now,
        )
        .update({"redeemed_at": now, "redeemed_from_ip": ip, "redeemed_endpoint_id": new_id}, synchronize_session=False)
    )
    if claimed != 1:
        raise _fail(session, status=409, code="already_used", message="This enrollment code was already used or is no longer valid.", request_id=rid, ip=ip)

    # ---- bind the request: the arbiter against a concurrent revoke ----
    bound = (
        session.query(EndpointRequest)
        .filter(EndpointRequest.id == rid, EndpointRequest.status.in_(_OPEN), EndpointRequest.endpoint_id.is_(None))
        .update({"status": STATUS_ENROLLED, "endpoint_id": new_id, "installed_at": now, "updated_at": now}, synchronize_session=False)
    )
    if bound != 1:
        raise _fail(session, status=403, code="revoked", message="This authorization is no longer valid.", request_id=rid, ip=ip)

    try:
        record, credential = endpoint_identity_service.create_enrolled_endpoint(
            session,
            endpoint_id=new_id,
            display_name=display_name,
            operating_system=operating_system,
            agent_version=agent_version,
            monitoring_scope=",".join(approved),
            request_id=rid,
        )
        session.flush()
    except (HTTPException, IntegrityError):
        raise _fail(session, status=409, code="endpoint_id_in_use", message="That endpoint id is already registered.", request_id=rid, ip=ip) from None

    audit_service.record(
        session,
        actor="agent",
        action="enrollment.redeemed",
        request_id=rid,
        target=new_id,
        detail=f"endpoint_id={new_id}; scope={','.join(approved)}; ip={ip}",
    )
    audit_service.notify(
        session,
        username=req.username,
        kind="request.enrolled",
        title="Agent enrolled",
        message=f"The agent on {display_name or 'your computer'} enrolled successfully with the approved scope: {', '.join(approved)}.",
        request_id=rid,
    )
    session.commit()
    logger.info("Endpoint %s enrolled through request %s", new_id, rid)
    return {
        "endpoint_id": record.endpoint_id,
        "agent_credential": credential,  # the ONLY time it exists in cleartext
        "credential_issued_at": record.credential_issued_at.isoformat() if record.credential_issued_at else None,
        "monitoring_scope": approved,
        "backend": settings.resolved_public_base_url or None,
    }
