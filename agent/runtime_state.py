"""
Small local record of the agent's own run history — last successful
collection and last successful upload — kept separate from:
  - identity.py (stable, rarely-changing identity fields)
  - credential_store.py (the secret itself)
  - state.py (the bounded pending-events buffer)
  - checkpoint.py (the per-category collection cursor)

Never stores API keys, credentials, passwords, or any event content —
only two timestamps, for `agent.py --status` to report honestly.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass

from paths import get_state_dir
from protected_storage import secure_storage_file

STATE_DIR = get_state_dir()
RUNTIME_STATE_FILE = STATE_DIR / "runtime_state.json"
logger = logging.getLogger(__name__)


@dataclass
class RuntimeState:
    last_successful_collection_at: str | None = None
    last_successful_upload_at: str | None = None


def load_runtime_state() -> RuntimeState:
    if not RUNTIME_STATE_FILE.exists():
        return RuntimeState()
    try:
        data = json.loads(RUNTIME_STATE_FILE.read_text(encoding="utf-8"))
        return RuntimeState(**data)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        logger.warning("Runtime status state is unreadable; reporting no saved timestamps.")
        return RuntimeState()


def save_runtime_state(state: RuntimeState) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    RUNTIME_STATE_FILE.touch(exist_ok=True)
    secure_storage_file(RUNTIME_STATE_FILE)
    RUNTIME_STATE_FILE.write_text(json.dumps(asdict(state), indent=2), encoding="utf-8")
    secure_storage_file(RUNTIME_STATE_FILE)


def record_successful_collection(when_iso: str) -> None:
    state = load_runtime_state()
    state.last_successful_collection_at = when_iso
    save_runtime_state(state)


def record_successful_upload(when_iso: str) -> None:
    state = load_runtime_state()
    state.last_successful_upload_at = when_iso
    save_runtime_state(state)
