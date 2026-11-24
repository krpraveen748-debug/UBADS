"""
Endpoint identity — foundation only (Phase 9).

This is genuinely new, backend-native data: log-collector's `storage.py`
owns the `events`/`behavior_features` tables (real collected telemetry);
this table only tracks WHICH Windows endpoints have registered with the
backend and when they were last heard from. It lives on
`backend/app/db/database.py`'s own SQLAlchemy Base/engine. The backend and
log-collector have separate metadata bases managed by Alembic against the
same configured database URL.

Deliberately excluded: no password, no hardware serial number/MAC address.
`endpoint_id` is a value the AGENT generates and persists locally (or the
server assigns one on first registration) — never derived from hardware
identifiers.

Phase 11 — per-agent credentials: each enrolled endpoint gets its OWN
random credential, issued once at enrollment. Only a SHA-256 verifier of
it (`credential_hash`) is stored here — never the credential itself — see
security/agent_auth.py for why a fast hash is appropriate for a 256-bit
random token (unlike a human password). A NULL `credential_hash` means a
pre-Phase-11 (legacy) record that has not been enrolled yet.
"""

from __future__ import annotations

from sqlalchemy import Column, DateTime, String

from app.db.database import Base


class EndpointRecord(Base):
    __tablename__ = "endpoints"

    endpoint_id = Column(String, primary_key=True)
    display_name = Column(String, nullable=True)
    operating_system = Column(String, nullable=True)
    agent_version = Column(String, nullable=True)
    # "registered" | "active" — a coarse status set by this service, NOT a
    # claim about real-time connectivity. See services/endpoint_identity_service.py
    # for the separate, derived "stale" label used for display purposes only.
    status = Column(String, nullable=False, default="registered")
    registered_at = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=True)

    # --- Phase 11: per-agent credential verifier (never the raw secret) ---
    credential_hash = Column(String, nullable=True)
    credential_issued_at = Column(DateTime(timezone=True), nullable=True)
    # Last time this endpoint successfully submitted an ingestion batch.
    last_ingest_at = Column(DateTime(timezone=True), nullable=True)

    # --- Phase 17 stage 4: enrolled through an approved request ---
    # Comma-separated approved monitoring scope; NULL = legacy endpoint (unrestricted,
    # exactly as before). When set, ingestion drops events outside it.
    monitoring_scope = Column(String, nullable=True)
    enrolled_request_id = Column(String, nullable=True)

