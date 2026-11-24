"""
Single-instance control and cooperative stop for the agent process.

- acquire_instance_lock(): an OS-level exclusive lock on a file in the
  state directory (msvcrt.locking). The OS releases it automatically if the
  process dies or is killed, so a crash can never leave the agent stuck as
  "running". Works the same for the scheduled task and a manual run.
- request_stop(): writes a stop flag the running loop checks every second,
  so a stop lets the current cycle finish (the checkpoint stays consistent).
"""

from __future__ import annotations

import msvcrt
import os
import time
from pathlib import Path

from paths import get_state_dir
from protected_storage import secure_storage_file

STATE_DIR = get_state_dir()


def _lock_path() -> Path:
    return STATE_DIR / "agent.lock"


def _pid_path() -> Path:
    return STATE_DIR / "agent.pid"


def _stop_path() -> Path:
    return STATE_DIR / "stop.flag"


def _try_lock(handle) -> bool:
    try:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        return True
    except OSError:
        return False


def _unlock(handle) -> None:
    try:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    except OSError:
        pass


class InstanceLock:
    def __init__(self, handle) -> None:
        self._handle = handle

    def release(self) -> None:
        _unlock(self._handle)
        self._handle.close()
        for path in (_pid_path(), _stop_path()):
            path.unlink(missing_ok=True)


def acquire_instance_lock() -> InstanceLock | None:
    """Returns the lock, or None if another agent instance holds it."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    handle = open(_lock_path(), "a+b")
    try:
        secure_storage_file(_lock_path())
        if not _try_lock(handle):
            handle.close()
            return None
        _pid_path().touch(exist_ok=True)
        secure_storage_file(_pid_path())
        _pid_path().write_text(str(os.getpid()), encoding="ascii")
        secure_storage_file(_pid_path())
        _stop_path().unlink(missing_ok=True)  # a stale flag must not stop a fresh start
    except Exception:
        _unlock(handle)
        handle.close()
        raise
    return InstanceLock(handle)


def running_pid() -> int | None:
    """PID of the running agent instance (-1 if running but PID unknown),
    or None if no instance is running."""
    if not _lock_path().exists():
        return None
    handle = open(_lock_path(), "a+b")
    try:
        if _try_lock(handle):
            _unlock(handle)
            return None
    finally:
        handle.close()
    try:
        return int(_pid_path().read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return -1


def request_stop() -> bool:
    """Asks the running instance to stop after its current cycle. Returns
    False (and writes nothing) if no instance is running."""
    if running_pid() is None:
        return False
    _stop_path().touch(exist_ok=True)
    secure_storage_file(_stop_path())
    _stop_path().write_text("stop", encoding="ascii")
    secure_storage_file(_stop_path())
    return True


def stop_requested() -> bool:
    return _stop_path().exists()


def wait_until_stopped(timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if running_pid() is None:
            return True
        time.sleep(0.5)
    return running_pid() is None
