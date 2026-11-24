"""
Phase 11 — persistent collection cursor/checkpoint.

Prior phases (2-10) re-read the same recent window of the Windows event
log every cycle and relied entirely on backend deduplication (event_uid)
to avoid re-storing already-seen events. That works but wastes work every
cycle forever. This module lets the agent remember, PER CATEGORY, the
highest Windows EventRecordID it has already collected and confirmed
delivered, so later cycles only ask Windows for events newer than that.

Design:
  - Keyed by (log_channel, category) — not by category alone, in case the
    agent is ever reconfigured to a different log channel; not a single
    global cursor, because collect_events() is called once per category
    with that category's own event IDs, so each has its own natural
    "highest record ID seen" sequence.
  - The cursor is Windows' own EventRecordID (see event_parser.py) — a
    strictly increasing per-channel-per-computer sequence number — NOT the
    event ID (4624 etc.), which is not unique or ordered at all. See
    log-collector/collector.py's collect_events(after_record_id=...).
  - Two-phase commit, matching the documented pipeline:
        collect (candidate cursor) -> validate -> send -> confirm -> advance
    `pending_advance()` computes what the cursor WOULD become; only
    `commit()` (called by agent.py after a confirmed successful backend
    response) actually persists it. A failed send simply never calls
    commit(), so the next cycle re-collects from the same, still-valid
    checkpoint — no event is skipped because a checkpoint moved too early.
  - Survives restarts: persisted to agent/.state/checkpoint.json, read
    fresh on every agent invocation (this is a short-lived CLI process,
    not a long-lived one with an in-memory-only cursor).
  - Corruption recovery: an unreadable/invalid checkpoint file is treated
    as "no checkpoint yet" (collect from the beginning of what's available,
    same as first run) rather than crashing the agent. This can cause some
    already-seen events to be re-collected once, but backend deduplication
    (storage.build_event_uid) makes that safe, never a duplicate stored row.
  - Log rollover / invalid cursor: if the channel's current newest
    EventRecordID is LOWER than a saved cursor, the log was cleared and
    record numbering restarted (see log-collector/storage.py's
    build_event_uid docstring for the same documented edge case). Detected
    via collector.get_newest_record_id() and handled by resetting that
    category's cursor to None (start collecting from whatever exists now)
    rather than requesting an impossible range or crashing.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from paths import get_state_dir
from protected_storage import secure_storage_file

logger = logging.getLogger(__name__)

STATE_DIR = get_state_dir()
CHECKPOINT_FILE = STATE_DIR / "checkpoint.json"


def _cursor_key(log_channel: str, category: str) -> str:
    return f"{log_channel}::{category}"


def load_checkpoint() -> dict[str, int]:
    """Returns {("log_channel::category"): last_confirmed_record_id}.
    A missing, empty, or corrupt file returns {} — safe recovery, not a
    crash (see module docstring)."""
    if not CHECKPOINT_FILE.exists():
        return {}
    try:
        data = json.loads(CHECKPOINT_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("checkpoint file did not contain a JSON object")
        return {str(k): int(v) for k, v in data.items()}
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        logger.error(
            "Checkpoint file is corrupt or unreadable (%s) — starting from no checkpoint for all "
            "categories. Already-delivered events will be re-collected once but never re-stored "
            "(backend deduplication).",
            exc,
        )
        return {}


def _save_checkpoint(data: dict[str, int]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp_path = CHECKPOINT_FILE.with_suffix(".json.tmp")
    tmp_path.touch(exist_ok=True)
    secure_storage_file(tmp_path)
    tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    secure_storage_file(tmp_path)
    tmp_path.replace(CHECKPOINT_FILE)  # atomic on both POSIX and Windows
    secure_storage_file(CHECKPOINT_FILE)


def get_cursor(log_channel: str, category: str) -> int | None:
    return load_checkpoint().get(_cursor_key(log_channel, category))


def reset_cursor(log_channel: str, category: str) -> None:
    """Used on detected log rollover (see check_for_rollover below)."""
    data = load_checkpoint()
    data.pop(_cursor_key(log_channel, category), None)
    _save_checkpoint(data)


def commit(log_channel: str, advances: dict[str, int]) -> None:
    """Persists new cursor values. `advances` maps category -> new highest
    confirmed EventRecordID. Only ever called AFTER a successful backend
    response for the batch containing those events — never before (see
    module docstring). Categories with no candidate this cycle are left
    untouched; a category is only ever moved forward, never backward."""
    if not advances:
        return
    data = load_checkpoint()
    for category, new_value in advances.items():
        key = _cursor_key(log_channel, category)
        current = data.get(key)
        if current is None or new_value > current:
            data[key] = new_value
    _save_checkpoint(data)


def check_for_rollover(log_channel: str, category: str, current_newest_record_id: int | None) -> bool:
    """Returns True (and resets the cursor) if the channel's current newest
    EventRecordID is lower than this category's saved cursor — the log was
    cleared/rolled over since the cursor was saved. `current_newest_record_id`
    is None when the channel is currently empty (nothing to compare against;
    not treated as rollover)."""
    if current_newest_record_id is None:
        return False
    cursor = get_cursor(log_channel, category)
    if cursor is not None and current_newest_record_id < cursor:
        logger.warning(
            "Detected log rollover on channel '%s' for category '%s' (newest record id %d < "
            "saved cursor %d) — resetting checkpoint for this category and collecting fresh.",
            log_channel,
            category,
            current_newest_record_id,
            cursor,
        )
        reset_cursor(log_channel, category)
        return True
    return False
