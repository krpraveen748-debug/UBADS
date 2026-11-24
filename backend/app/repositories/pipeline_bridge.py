"""
Bridges the FastAPI backend to the existing log-collector (SQLite
repository) and ml-service (feature engineering / readiness reporting)
modules, WITHOUT duplicating any of their logic.

`log-collector/` and `ml-service/` are both hyphenated directory names —
not valid Python packages — so this project's established pattern (see
ml-service/feature_engineering.py) is to add them to sys.path directly and
import their modules as plain top-level names. This file does that once,
at import time, so every backend route reuses the exact same `storage`
repository, `collection_status`/`data_quality`/
`user_classification_diagnostics`/`baseline_stats`/`user_identity` logic
those CLIs already use — never a re-implementation of the same rules.

Phase 8C: only ever READS via these modules' existing query functions
(storage.get_all_events, storage.query_events, storage.get_feature_records,
...) — no route wrote to the events table.

Phase 10: POST /api/ingest/events (see api/ingest.py) is the one exception
— it validates (validation.validate_event) and stores
(storage.insert_event) real agent-submitted events using the exact same
functions log-collector/collector.py already uses for its own local
pipeline. No new insert/validation logic was written; no synthetic/demo
data is ever passed through this bridge.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
_LOG_COLLECTOR_DIR = PROJECT_ROOT / "log-collector"
_ML_SERVICE_DIR = PROJECT_ROOT / "ml-service"

for _dir in (_LOG_COLLECTOR_DIR, _ML_SERVICE_DIR):
    _dir_str = str(_dir)
    if _dir_str not in sys.path:
        sys.path.insert(0, _dir_str)

import storage  # noqa: E402  (log-collector's repository layer — see module docstring)
import event_parser  # noqa: E402  (authoritative event_id -> category map; Stage 4G scope enforcement)
import validation  # noqa: E402  (log-collector's event validation — reused by Phase 10 ingestion)
import baseline_stats  # noqa: E402
import collection_status  # noqa: E402
import data_quality  # noqa: E402
import user_classification_diagnostics  # noqa: E402
import user_identity  # noqa: E402

__all__ = [
    "storage",
    "event_parser",
    "validation",
    "baseline_stats",
    "collection_status",
    "data_quality",
    "user_classification_diagnostics",
    "user_identity",
    "get_session",
]


def get_session():
    """FastAPI dependency — one storage.SessionLocal() per request, always
    closed. Reuses log-collector's own session factory (bound to the same
    data/app.db every other component uses), not a second connection."""
    session = storage.SessionLocal()
    try:
        yield session
    finally:
        session.close()
