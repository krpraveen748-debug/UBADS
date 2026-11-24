from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator

_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,64}$")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")


class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str
    full_name: str = Field(min_length=1, max_length=120)
    organization: str = Field(min_length=2, max_length=120)

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        v = v.strip()
        if not _USERNAME_RE.match(v):
            raise ValueError("Username must be 3-64 characters: letters, digits, '.', '_' or '-'.")
        return v

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip()
        if not _EMAIL_RE.match(v):
            raise ValueError("Enter a valid email address.")
        return v

    @field_validator("full_name", "organization")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class ClientHint(BaseModel):
    """Optional, UNVERIFIED browser-side compatibility check. The website
    cannot reliably know the Windows computer name; the agent reports that."""

    platform: str | None = Field(default=None, max_length=60)
    is_windows: bool | None = None
    user_agent: str | None = Field(default=None, max_length=300)


class EndpointRequestCreate(BaseModel):
    organization: str | None = Field(default=None, min_length=2, max_length=120)
    department: str | None = Field(default=None, max_length=120)
    justification: str | None = Field(default=None, max_length=1000)
    requested_scope: list[str] = Field(min_length=1)
    consent_acknowledged: bool
    client_hint: ClientHint | None = None


class EndpointRequestOut(BaseModel):
    id: str
    status: str
    username: str
    organization: str
    department: str | None = None
    justification: str | None = None
    requested_scope: list[str]
    approved_scope: list[str] | None = None
    status_reason: str | None = None
    decided_by: str | None = None
    decided_at: str | None = None
    approval_expires_at: str | None = None
    created_at: str
    endpoint_id: str | None = None
    installed_at: str | None = None
    # Separate concept from `status`: live connectivity of the installed endpoint.
    endpoint_connection_status: str | None = None
    consent_version: str
    client_hint: dict | None = None
