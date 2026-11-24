"""
Dashboard authentication (human operators) — SEPARATE from agent auth
(security/agent_auth.py). Agents use X-Endpoint-Id/X-Agent-Credential and
can never read dashboard APIs; dashboard sessions can never ingest.

- Passwords: scrypt (stdlib) with a per-user random salt; constant-time compare.
- Login issues a random 256-bit bearer token; only its SHA-256 is stored
  server-side, with an expiry (DASHBOARD_SESSION_HOURS). Logout deletes it.
- Failed logins are rate-limited per username (in-memory, per process).
- Unknown user and wrong password produce the identical 401.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import get_db
from app.security import rate_limit
from app.models.dashboard_auth import ROLE_ADMIN, ROLE_USER, DashboardSession, DashboardUser

logger = logging.getLogger(__name__)

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1
_INVALID_LOGIN = "Invalid username or password."
_UNAUTHORIZED = "Authentication required."
_BEARER = {"WWW-Authenticate": "Bearer"}


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N, _SCRYPT_R, _SCRYPT_P, base64.b64encode(salt).decode(), base64.b64encode(digest).decode()
    )


def verify_password(password: str, stored: str | None) -> bool:
    try:
        scheme, n, r, p, salt_b64, digest_b64 = (stored or "").split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest_b64)
        actual = hashlib.scrypt(
            password.encode(), salt=base64.b64decode(salt_b64), n=int(n), r=int(r), p=int(p), dklen=len(expected)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


# Verified against when the username is unknown, so response time does not
# reveal whether an account exists.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(8))


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def create_user(
    session: Session,
    username: str,
    password: str,
    *,
    role: str = ROLE_ADMIN,
    email: str | None = None,
    full_name: str | None = None,
    organization: str | None = None,
) -> None:
    """Creates a dashboard user, or resets the password (and signs out all
    sessions) of an existing one. Defaults to role admin because this is the
    operator CLI / test path; self-registration passes role="user"."""
    username = username.strip()
    if not username:
        raise ValueError("Username is required.")
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters.")
    if role not in (ROLE_ADMIN, ROLE_USER):
        raise ValueError("Unknown role.")
    user = session.get(DashboardUser, username)
    if user is None:
        session.add(
            DashboardUser(
                username=username,
                password_hash=hash_password(password),
                created_at=datetime.now(timezone.utc),
                role=role,
                email=email,
                full_name=full_name,
                organization=organization,
            )
        )
    else:
        user.password_hash = hash_password(password)
        session.query(DashboardSession).filter(DashboardSession.username == username).delete()
    session.commit()


def _check_login_limits(key: str, ip: str) -> None:
    """Raises 429 (with Retry-After) if this attempt is throttled. Applies
    identically whether or not the username exists, so it reveals nothing
    about accounts. Every limit is a sliding window that expires by itself."""
    window = settings.dashboard_login_lockout_seconds
    pair = f"{key}|{ip}"
    known = rate_limit.known_good_logins.count(pair, settings.dashboard_known_ip_days * 86400) > 0
    checks = [
        (rate_limit.login_failures_pair, pair, settings.dashboard_login_max_failures),
        (rate_limit.login_failures_ip, ip, settings.dashboard_login_max_failures_per_ip),
    ]
    if not known:  # the cross-IP per-username cap never blocks the user's own usual IP
        checks.append((rate_limit.login_failures_user, key, settings.dashboard_login_max_failures_per_user))
    for limiter, limiter_key, limit in checks:
        if limiter.is_limited(limiter_key, limit, window):
            raise HTTPException(
                status_code=429,
                detail="Too many failed login attempts. Try again later.",
                headers={"Retry-After": str(limiter.retry_after(limiter_key, window))},
            )


def unlock_username(username: str) -> int:
    """Admin recovery: clears the throttle counters for a username on every IP
    (it does not touch the password or sessions). Returns counters cleared."""
    key = (username or "").strip().lower()
    cleared = rate_limit.login_failures_user.clear_matching(lambda k: k == key)
    cleared += rate_limit.login_failures_pair.clear_matching(lambda k: k.startswith(f"{key}|"))
    return cleared


def login(session: Session, username: str, password: str, ip: str = "unknown") -> dict:
    name = (username or "").strip()
    key = name.lower()
    _check_login_limits(key, ip)
    user = session.get(DashboardUser, name)
    ok = verify_password(password, user.password_hash if user else _DUMMY_HASH)
    window = settings.dashboard_login_lockout_seconds
    if user is None or not ok:
        rate_limit.login_failures_pair.hit(f"{key}|{ip}", window)
        rate_limit.login_failures_ip.hit(ip, window)
        rate_limit.login_failures_user.hit(key, window)
        logger.warning("Failed dashboard login attempt.")
        raise HTTPException(status_code=401, detail=_INVALID_LOGIN)
    rate_limit.login_failures_pair.clear(f"{key}|{ip}")
    rate_limit.known_good_logins.hit(f"{key}|{ip}", settings.dashboard_known_ip_days * 86400)

    now = datetime.now(timezone.utc)
    session.query(DashboardSession).filter(DashboardSession.expires_at < now).delete()
    token = secrets.token_urlsafe(32)
    expires = now + timedelta(hours=settings.dashboard_session_hours)
    session.add(DashboardSession(token_hash=_hash_token(token), username=user.username, created_at=now, expires_at=expires))
    session.commit()
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires.isoformat(),
        "username": user.username,
        "role": user.role,
    }


def revoke_token(session: Session, token: str) -> None:
    session.query(DashboardSession).filter(DashboardSession.token_hash == _hash_token(token)).delete()
    session.commit()


def bearer_token(authorization: str | None) -> str:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=401, detail=_UNAUTHORIZED, headers=_BEARER)
    return token.strip()


def require_dashboard_user(
    authorization: str | None = Header(default=None), session: Session = Depends(get_db)
) -> str:
    """Returns the authenticated dashboard username or raises 401."""
    token = bearer_token(authorization)
    record = session.query(DashboardSession).filter(DashboardSession.token_hash == _hash_token(token)).first()
    if record is None:
        raise HTTPException(status_code=401, detail=_UNAUTHORIZED, headers=_BEARER)
    if _aware(record.expires_at) <= datetime.now(timezone.utc):
        session.delete(record)
        session.commit()
        raise HTTPException(status_code=401, detail="Session expired. Please sign in again.", headers=_BEARER)
    return record.username


def get_current_user(
    authorization: str | None = Header(default=None), session: Session = Depends(get_db)
) -> DashboardUser:
    """The authenticated DashboardUser row (any role)."""
    username = require_dashboard_user(authorization, session)
    user = session.get(DashboardUser, username)
    if user is None:  # account deleted while a session was still live
        raise HTTPException(status_code=401, detail=_UNAUTHORIZED, headers=_BEARER)
    return user


def require_admin(user: DashboardUser = Depends(get_current_user)) -> DashboardUser:
    """Administrators only: 401 if not signed in, 403 for a normal user."""
    if user.role != ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="Administrator access required.")
    return user
