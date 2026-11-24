"""
Simple, bounded local buffer for events that couldn't be sent to the
backend (e.g. it was temporarily unavailable). Deliberately NOT a
distributed queue — just a capped JSON-lines file, so a later run can
retry the same events instead of losing them, without unbounded local
growth if the backend stays down for a long time.
"""

from __future__ import annotations

import json
import logging
import os
import stat
import tempfile
import time
from pathlib import Path

from paths import get_state_dir
from protected_storage import secure_storage_file

logger = logging.getLogger(__name__)

STATE_DIR = get_state_dir()
PENDING_FILE = STATE_DIR / "pending_events.jsonl"
MAX_PENDING_EVENTS = 500


class PendingStateError(RuntimeError):
    """Pending event data is unreadable and must not be overwritten."""


def _cleanup_abandoned_pending_temps() -> None:
    abandoned_before = time.time() - 24 * 60 * 60
    try:
        for candidate in STATE_DIR.glob(".pending_events-*.tmp"):
            try:
                details = candidate.lstat()
            except OSError:
                logger.warning("An abandoned pending-event temporary file could not be inspected.")
                continue
            if not stat.S_ISREG(details.st_mode) or details.st_mtime >= abandoned_before:
                continue
            try:
                candidate.unlink()
            except OSError:
                logger.warning("An abandoned pending-event temporary file could not be removed.")
    except OSError:
        logger.warning("Abandoned pending-event temporary files could not be inspected.")


def load_pending() -> list[dict]:
    if not PENDING_FILE.exists():
        return []
    try:
        events = []
        for line in PENDING_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("pending event was not a JSON object")
                events.append(event)
        return events
    except (OSError, UnicodeError, ValueError) as exc:
        logger.error("Pending event buffer is unreadable; preserving the original file.")
        raise PendingStateError("Pending event state is unreadable; the original buffer was left unchanged.") from exc


def save_pending(events: list[dict]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    # Bounded: keep only the most recent MAX_PENDING_EVENTS if over the cap,
    # rather than growing forever while the backend is unreachable.
    capped = events[-MAX_PENDING_EVENTS:]
    serialized = "".join(json.dumps(event, ensure_ascii=False) + "\n" for event in capped)
    fd, temp_name = tempfile.mkstemp(
        prefix=".pending_events-", suffix=".tmp", dir=STATE_DIR
    )
    temp_path: Path | None = Path(temp_name)
    try:
        secure_storage_file(temp_path)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            fd = -1
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, PENDING_FILE)
        temp_path = None
        _cleanup_abandoned_pending_temps()
    except OSError as exc:
        raise PendingStateError(
            "Pending event state could not be updated; the original buffer was preserved."
        ) from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                logger.warning("A failed pending-event temporary file could not be removed.")


def append_pending(new_events: list[dict]) -> int:
    """Adds new_events to the buffer (capped). Returns the number actually
    kept after applying the cap (older events are dropped first)."""
    combined = load_pending() + new_events
    save_pending(combined)
    return len(load_pending())


def clear_pending() -> None:
    if PENDING_FILE.exists():
        PENDING_FILE.unlink()
