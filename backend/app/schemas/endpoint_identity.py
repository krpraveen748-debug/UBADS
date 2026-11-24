from __future__ import annotations

from pydantic import BaseModel


class EndpointRegisterRequest(BaseModel):
    """`endpoint_id` is optional: omit it on first enrollment to receive a
    server-generated one (the agent then persists it locally). When the
    request is authenticated with a per-agent credential, `endpoint_id`
    (if present) must match the authenticated endpoint — see
    app/security/agent_auth.py."""

    endpoint_id: str | None = None
    display_name: str | None = None
    operating_system: str | None = None
    agent_version: str | None = None


class EndpointHeartbeatRequest(BaseModel):
    """The endpoint is identified by its credential headers. `endpoint_id`
    is optional and, if sent, must match the authenticated endpoint."""

    endpoint_id: str | None = None


class EndpointIdentity(BaseModel):
    endpoint_id: str
    display_name: str | None = None
    operating_system: str | None = None
    agent_version: str | None = None
    status: str
    registered_at: str
    last_seen: str | None = None
    credential_enrolled: bool = False
    credential_issued_at: str | None = None
    last_ingest_at: str | None = None
    connection_status: str = "offline"  # not_enrolled | online | stale | offline
    monitoring_scope: list[str] | None = None  # None = legacy endpoint, unrestricted


class EndpointRegistrationResponse(EndpointIdentity):
    """`agent_credential` is present ONLY in the response that issues it
    (first enrollment). It is never stored server-side and never returned
    again — the agent must persist it (agent/credential_store.py)."""

    agent_credential: str | None = None
