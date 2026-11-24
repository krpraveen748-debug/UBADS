"""
Stable local endpoint identity — persisted across agent restarts.

Deliberately NOT derived from:
  - username (a user, not the endpoint, could change)
  - IP address (not permanent — changes with network/DHCP)
  - MAC address or any other hardware serial (not collected at all)

`endpoint_id` is a randomly generated UUID4, generated once and persisted
to a local JSON file in the selected agent state directory. Every
subsequent run reads the same file rather than generating a new ID — this
is what makes the identity "survive restarts" as required.

`display_name` and `operating_system` use `platform.node()` /
`platform.platform()` — the same computer name (`computer_name`) already
recorded on every event this project collects (Phase 2+), not a new
hardware identifier. `ENDPOINT_ID` may be set explicitly via config to
override the generated one in development/test mode. Installed production
agents use only their protected persisted identity.
"""

from __future__ import annotations

import json
import platform
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from config import settings
import paths
from protected_storage import secure_storage_file
from paths import get_state_dir

AGENT_VERSION = "0.1.0"

STATE_DIR = get_state_dir()
IDENTITY_FILE = STATE_DIR / "identity.json"


class IdentityStateError(RuntimeError):
    """Existing endpoint state is incomplete or corrupt; identity was not replaced."""


@dataclass
class EndpointIdentity:
    endpoint_id: str
    display_name: str
    operating_system: str
    agent_version: str
    created_at: str


def _generate_identity() -> EndpointIdentity:
    return EndpointIdentity(
        endpoint_id=settings.endpoint_id or str(uuid.uuid4()),
        display_name=platform.node() or "unknown-endpoint",
        operating_system=platform.platform(),
        agent_version=AGENT_VERSION,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def load_or_create_identity() -> EndpointIdentity:
    """Reads the persisted identity if present; otherwise generates one and
    persists it. If ENDPOINT_ID is configured explicitly and differs from
    whatever was previously persisted, development/test mode updates the
    persisted file to match it. Installed production ignores that override."""
    if IDENTITY_FILE.exists():
        try:
            data = json.loads(IDENTITY_FILE.read_text(encoding="utf-8"))
            identity = EndpointIdentity(**data)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise IdentityStateError("The stored endpoint identity is unreadable; it was not replaced.") from exc
        if settings.endpoint_id and identity.endpoint_id != settings.endpoint_id:
            identity.endpoint_id = settings.endpoint_id
            _save_identity(identity)
        return identity

    if paths.is_frozen_production():
        try:
            from credential_store import CREDENTIAL_FILE

            has_credential = CREDENTIAL_FILE.exists()
            has_local_state = STATE_DIR.exists() and any(STATE_DIR.iterdir())
            legacy_state = paths.get_legacy_state_dir()
            has_legacy_state = legacy_state.exists() and any(legacy_state.iterdir())
        except OSError as exc:
            raise IdentityStateError("Existing endpoint state could not be checked; no identity was created.") from exc
        if has_credential or has_local_state or has_legacy_state:
            raise IdentityStateError(
                "Existing endpoint state is incomplete; identity was not replaced. Administrator recovery is required."
            )

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    identity = _generate_identity()
    _save_identity(identity)
    return identity


def adopt_endpoint_id(endpoint_id: str) -> EndpointIdentity:
    """Stage 4D: the server confirmed a (different) id for this endpoint during
    enrollment; record it. Display name, OS, creation time are preserved."""
    identity = load_or_create_identity()
    if identity.endpoint_id != endpoint_id:
        identity.endpoint_id = endpoint_id
        _save_identity(identity)
    return identity


def _save_identity(identity: EndpointIdentity) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    IDENTITY_FILE.touch(exist_ok=True)
    secure_storage_file(IDENTITY_FILE)
    IDENTITY_FILE.write_text(json.dumps(asdict(identity), indent=2), encoding="utf-8")
    secure_storage_file(IDENTITY_FILE)
