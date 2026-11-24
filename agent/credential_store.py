"""
Phase 11 — local storage for this endpoint's OWN per-agent credential.

Separate from identity.py (which only holds non-secret identity fields):
this file is the one place on disk that ever holds the credential value
the backend verifies.

Phase 16 — the credential is protected with Windows DPAPI (user scope):
only the same Windows user on the same computer can decrypt it, so a copied
credentials.json is useless elsewhere and is never readable as plain text.
A legacy plain-text file (written by earlier phases) is still readable and
is re-written protected the first time it is loaded.

Never logs the credential value. Never sends it anywhere except as the
X-Agent-Credential header to THIS agent's own configured backend_url (see
backend_client.py).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from paths import get_state_dir
from protected_storage import secure_storage_file

logger = logging.getLogger(__name__)

STATE_DIR = get_state_dir()
CREDENTIAL_FILE = STATE_DIR / "credentials.json"

_ENTROPY = b"UBADS-agent-credential-v1"
_PROTECTION = "dpapi-user"


class CredentialStateError(RuntimeError):
    """Stored credential state is unsafe to use or modify."""


class CredentialProtectionUnavailable(CredentialStateError):
    """DPAPI (pywin32 win32crypt) is not available - refusing to store the
    credential as plain text."""


class CredentialCorruptError(CredentialStateError):
    """Stored credential state is malformed or cannot be decrypted."""


class CredentialInaccessibleError(CredentialStateError):
    """Stored credential state cannot be accessed."""


class CredentialAlreadyExistsError(CredentialStateError):
    """A credential already exists and was not overwritten."""


@dataclass
class AgentCredential:
    endpoint_id: str
    agent_credential: str
    issued_at: str | None = None

    def __repr__(self) -> str:  # never leak the secret via logs/tracebacks
        return f"AgentCredential(endpoint_id={self.endpoint_id!r}, agent_credential=<hidden>)"


def _crypt():
    try:
        import win32crypt
    except ImportError as exc:  # pragma: no cover - non-Windows
        raise CredentialProtectionUnavailable("Windows DPAPI (pywin32) is required to store credentials.") from exc
    return win32crypt


def _protect(secret: str) -> str:
    blob = _crypt().CryptProtectData(secret.encode("utf-8"), "UBADS agent credential", _ENTROPY, None, None, 0)
    return base64.b64encode(blob).decode("ascii")


def _unprotect(token: str) -> str:
    _desc, data = _crypt().CryptUnprotectData(base64.b64decode(token), _ENTROPY, None, None, 0)
    return data.decode("utf-8")


def protection_self_test() -> bool:
    """True if DPAPI can protect and unprotect a throwaway value for the current user
    (used by enrollment BEFORE it spends a one-time code)."""
    try:
        return _unprotect(_protect("ubads-dpapi-self-test")) == "ubads-dpapi-self-test"
    except Exception:  # noqa: BLE001
        return False


def load_credential() -> AgentCredential | None:
    """Return a credential, or None only when the credential file is missing."""
    try:
        raw = CREDENTIAL_FILE.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        logger.error("Stored agent credential is inaccessible.")
        raise CredentialInaccessibleError(
            "Stored agent credential is inaccessible; enrollment was stopped."
        ) from exc
    except UnicodeError as exc:
        logger.error("Stored agent credential is corrupt.")
        raise CredentialCorruptError(
            "Stored agent credential is corrupt and enrollment was stopped."
        ) from exc

    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("credential data must be an object")
        protection = data.get("protection")
        if protection == _PROTECTION:
            credential = AgentCredential(
                endpoint_id=data["endpoint_id"],
                agent_credential=_unprotect(data["agent_credential_protected"]),
                issued_at=data.get("issued_at"),
            )
        elif "protection" not in data:
            credential = AgentCredential(
                endpoint_id=data["endpoint_id"],
                agent_credential=data["agent_credential"],
                issued_at=data.get("issued_at"),
            )
        else:
            raise ValueError("credential protection format is unsupported")
        if (
            not isinstance(credential.endpoint_id, str)
            or not credential.endpoint_id
            or not isinstance(credential.agent_credential, str)
            or not credential.agent_credential
            or (credential.issued_at is not None and not isinstance(credential.issued_at, str))
        ):
            raise ValueError("credential fields are invalid")
    except CredentialProtectionUnavailable:
        raise
    except Exception as exc:  # malformed data, wrong keys, or DPAPI decrypt failure
        logger.error("Stored agent credential is corrupt or cannot be decrypted.")
        raise CredentialCorruptError(
            "Stored agent credential is corrupt or cannot be decrypted; enrollment was stopped."
        ) from exc

    if "protection" not in data:
        _write_credential(
            credential.endpoint_id,
            credential.agent_credential,
            credential.issued_at,
            replace_existing=True,
        )
        logger.info("Upgraded stored agent credential to DPAPI protection.")
    return credential


def save_credential(endpoint_id: str, agent_credential: str, issued_at: str | None = None) -> None:
    _write_credential(endpoint_id, agent_credential, issued_at, replace_existing=False)


def _write_credential(
    endpoint_id: str,
    agent_credential: str,
    issued_at: str | None,
    *,
    replace_existing: bool,
) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "endpoint_id": endpoint_id,
        "issued_at": issued_at,
        "protection": _PROTECTION,
        "agent_credential_protected": _protect(agent_credential),
    }
    encoded = json.dumps(payload, indent=2).encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=".credentials-", suffix=".tmp", dir=STATE_DIR)
    temp_path: Path | None = Path(temp_name)
    try:
        secure_storage_file(temp_path)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        if replace_existing:
            os.replace(temp_path, CREDENTIAL_FILE)
        else:
            try:
                os.link(temp_path, CREDENTIAL_FILE)
            except FileExistsError as exc:
                raise CredentialAlreadyExistsError(
                    "A stored agent credential already exists; it was not overwritten."
                ) from exc
        temp_path.unlink(missing_ok=True)
        temp_path = None
        secure_storage_file(CREDENTIAL_FILE)
    except OSError as exc:
        raise CredentialInaccessibleError(
            "Stored agent credential could not be saved securely."
        ) from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                logger.warning("A temporary credential file could not be removed.")


def clear_credential() -> None:
    if CREDENTIAL_FILE.exists():
        CREDENTIAL_FILE.unlink()
