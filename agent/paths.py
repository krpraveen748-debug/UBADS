"""Canonical paths for source, isolated test, and installed agent modes."""

from __future__ import annotations

import ctypes
import json
import os
import sys
from pathlib import Path

_SOURCE_STATE_DIR = Path(__file__).resolve().parent / ".state"
DEFAULT_TASK_NAME = "UBADS Agent"
_PROGRAM_DATA_CSIDL = 0x23
_LOCAL_APP_DATA_CSIDL = 0x1C


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def is_test_mode() -> bool:
    return not is_frozen() and "pytest" in sys.modules


def _install_profile() -> dict:
    if not is_frozen():
        return {}
    try:
        profile = json.loads(
            (Path(sys.executable).resolve().parent / "ubads-agent.profile").read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        return {}
    return profile if isinstance(profile, dict) else {}


def is_frozen_test() -> bool:
    """Only an explicit test-build profile enables frozen path overrides."""
    return is_frozen() and _install_profile().get("mode") == "test"


def is_frozen_production() -> bool:
    return is_frozen() and not is_frozen_test()


def _known_folder(csid: int) -> Path:
    if os.name != "nt":
        raise RuntimeError("Windows known folders are required for an installed agent.")
    folder = ctypes.create_unicode_buffer(32768)
    result = ctypes.windll.shell32.SHGetFolderPathW(None, csid, None, 0, folder)
    if result != 0 or not folder.value:
        raise RuntimeError("Windows could not resolve the required agent storage folder.")
    return Path(folder.value)


def get_program_data_dir() -> Path:
    return _known_folder(_PROGRAM_DATA_CSIDL)


def get_legacy_state_dir() -> Path:
    """Read-only compatibility probe for state from pre-4H-2 installations."""
    return _known_folder(_LOCAL_APP_DATA_CSIDL) / "UBADS" / "Agent" / ".state"


def get_task_name() -> str:
    if not is_frozen():
        name = os.environ.get("UBADS_TASK_NAME")
    elif is_frozen_test():
        name = os.environ.get("UBADS_TASK_NAME") or _install_profile().get("task_name")
    else:
        name = None
    return name.strip() if isinstance(name, str) and name.strip() else DEFAULT_TASK_NAME


def get_agent_root() -> Path:
    if not is_frozen():
        override = os.environ.get("UBADS_STATE_DIR")
        if override:
            return Path(override).parent
        return _SOURCE_STATE_DIR.parent
    if is_frozen_test():
        profile_state = _install_profile().get("state_dir")
        override = os.environ.get("UBADS_STATE_DIR")
        if override:
            return Path(override).parent
        if isinstance(profile_state, str) and profile_state.strip():
            return Path(profile_state).parent
        return Path(sys.executable).resolve().parent / ".state"
    return get_program_data_dir() / "UBADS" / "Agent"


def get_state_dir() -> Path:
    if not is_frozen():
        override = os.environ.get("UBADS_STATE_DIR")
        return Path(override) if override else _SOURCE_STATE_DIR
    if is_frozen_test():
        override = os.environ.get("UBADS_STATE_DIR")
        if override:
            return Path(override)
        profile_state = _install_profile().get("state_dir")
        if isinstance(profile_state, str) and profile_state.strip():
            return Path(profile_state)
        return get_agent_root() / "state"
    return get_agent_root() / "state"


def get_config_dir() -> Path:
    if not is_frozen():
        return Path(__file__).resolve().parent.parent / "config"
    if is_frozen_test():
        return Path(sys.executable).resolve().parent
    return get_agent_root() / "config"


def get_trusted_config_path() -> Path:
    if is_frozen_production():
        return get_config_dir() / "agent.json"
    return get_config_dir() / ".env"


def get_user_config_path() -> Path:
    """Path used by the setup/enrollment writer (JSON in installed production)."""
    if is_frozen_production():
        return get_trusted_config_path()
    return get_state_dir().parent / "agent.env"


def get_log_dir() -> Path:
    if is_frozen():
        return get_agent_root() / "logs"
    return get_state_dir().parent / "logs"
