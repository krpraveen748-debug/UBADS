"""
Agent authentication — Phase 11 per-agent credentials.

    Enrollment (once per endpoint):
        Agent --X-Agent-Api-Key: <shared ENROLLMENT key>--> POST /api/endpoints/register
        Backend creates the endpoint, generates a random per-agent credential,
        stores ONLY its SHA-256 verifier, returns the credential ONCE.

    Every later call (heartbeat, ingest, metadata re-registration):
        Agent --X-Endpoint-Id: <id>, X-Agent-Credential: <its own secret>--> backend
        require_authenticated_endpoint() verifies the pair and returns the
        endpoint record. Routes act ONLY on that authenticated endpoint —
        an `endpoint_id` in a request body is never trusted on its own.

So: Endpoint A -> credential A, Endpoint B -> credential B. Knowing
endpoint B's ID is useless without B's credential, and changing
ENDPOINT_ID on agent A does not let it act as B.

`AGENT_API_KEY` (the Phase 9/10 shared secret) is kept, but its role is
narrowed to an ENROLLMENT key: it can only create a NEW endpoint (or
one-time-enroll a pre-Phase-11 legacy record that has no credential yet).
It is no longer accepted for heartbeat or ingestion, and it can never
overwrite or re-key an endpoint that already holds a credential (409).
Secure-by-default is preserved: with AGENT_API_KEY unset, enrollment is
closed (503); already-enrolled agents keep working with their own
credentials.

Why SHA-256 and not bcrypt/PBKDF2: those slow hashes exist to protect
LOW-entropy human passwords from offline guessing. The credential here is
32 bytes from `secrets.token_urlsafe` (256 bits of entropy), which cannot
be brute-forced regardless of hash speed — the same approach used for API
tokens by most platforms. Comparison uses hmac.compare_digest (constant
time).

Never logs a key or credential value — only accept/reject and why.
This is a development-grade foundation, not production secret management
(no rotation schedule, no HSM/KMS, no rate limiting) — see backend/README.md.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import get_db
from app.models.endpoint import EndpointRecord

logger = logging.getLogger(__name__)

ENROLLMENT_KEY_HEADER = "X-Agent-Api-Key"
ENDPOINT_ID_HEADER = "X-Endpoint-Id"
AGENT_CREDENTIAL_HEADER = "X-Agent-Credential"

_HASH_PREFIX = "sha256:"
_INVALID_CREDENTIAL_DETAIL = "Invalid or missing agent credential."


def generate_agent_credential() -> str:
    return secrets.token_urlsafe(32)


def hash_agent_credential(credential: str) -> str:
    return _HASH_PREFIX + hashlib.sha256(credential.encode("utf-8")).hexdigest()


def verify_agent_credential(credential: str | None, stored_hash: str | None) -> bool:
    if not credential or not stored_hash:
        return False
    return hmac.compare_digest(hash_agent_credential(credential), stored_hash)


def check_enrollment_key(provided_key: str | None) -> None:
    """Validates the shared ENROLLMENT key (AGENT_API_KEY). 503 if the
    server has none configured (enrollment closed), 401 if wrong/missing."""
    configured_key = settings.agent_api_key
    if not configured_key:
        logger.warning("Enrollment attempted but AGENT_API_KEY is not configured — rejecting.")
        raise HTTPException(
            status_code=503,
            detail="Agent authentication is not configured on this server.",
        )
    if not provided_key or not hmac.compare_digest(provided_key, configured_key):
        logger.warning("Enrollment attempted with a missing or invalid enrollment key — rejecting.")
        raise HTTPException(status_code=401, detail="Invalid or missing agent API key.")


def authenticate_endpoint(session: Session, endpoint_id: str | None, credential: str | None) -> EndpointRecord:
    """Returns the endpoint record iff (endpoint_id, credential) is a valid
    pair. Every failure — unknown endpoint, legacy endpoint with no
    credential yet, wrong credential, missing header — gets the SAME 401,
    so a caller cannot probe which endpoint IDs exist."""
    if not endpoint_id or not credential:
        raise HTTPException(status_code=401, detail=_INVALID_CREDENTIAL_DETAIL)
    record = session.get(EndpointRecord, endpoint_id)
    if record is None or record.status == "revoked" or not verify_agent_credential(credential, record.credential_hash):
        logger.warning("Rejected agent request: invalid credential for claimed endpoint.")
        raise HTTPException(status_code=401, detail=_INVALID_CREDENTIAL_DETAIL)
    return record


def require_authenticated_endpoint(
    x_endpoint_id: str | None = Header(default=None, alias=ENDPOINT_ID_HEADER),
    x_agent_credential: str | None = Header(default=None, alias=AGENT_CREDENTIAL_HEADER),
    session: Session = Depends(get_db),
) -> EndpointRecord:
    return authenticate_endpoint(session, x_endpoint_id, x_agent_credential)


def reject_mismatched_endpoint_id(claimed_endpoint_id: str | None, authenticated: EndpointRecord) -> None:
    """A body-supplied endpoint_id is optional; if present it MUST equal the
    authenticated endpoint. Anything else is an impersonation attempt."""
    if claimed_endpoint_id is not None and claimed_endpoint_id != authenticated.endpoint_id:
        logger.warning(
            "Endpoint %s attempted to act as a different endpoint_id — rejecting.", authenticated.endpoint_id
        )
        raise HTTPException(
            status_code=403,
            detail="endpoint_id does not match the authenticated endpoint.",
        )
