"""
Bridges the Windows agent to the existing log-collector modules, WITHOUT
duplicating any of their logic — the exact same pattern
backend/app/repositories/pipeline_bridge.py already uses for the backend.

`log-collector/` is a hyphenated directory name — not a valid Python
package — so this adds it to sys.path and imports its modules as plain
top-level names.

The agent reuses:
  - collector.collect_events() / CATEGORY_EVENT_IDS  — real Windows Event
    Log querying (win32evtlog), exactly as log-collector/collector.py's
    own CLI uses it.
  - event_parser.normalize_event() (used internally by collect_events())
    and validation.validate_event() — the same normalization/validation
    rules the local collector CLI enforces before writing to SQLite.

Note: importing `collector` transitively imports log-collector's
`storage.py` (since collector.py itself supports a local --show/--dry-run
mode backed by SQLite). This means a local SQLAlchemy engine object is
created as a side effect of import, but the agent itself never calls any
storage.* write function — collected events are sent to the backend over
HTTP (see backend_client.py), never written to a local database by this
module. Nothing here inserts into the local data/app.db. (SQLAlchemy's
create_engine() for SQLite is lazy — it does not touch the filesystem
until a query actually runs, so this is harmless even under a packaged
executable where the resulting path is inside a temporary directory; see
below.)

Phase 13 — packaged executable: when running from source, `log-collector/`
is this project's normal sibling directory next to `agent/`. When frozen
by PyInstaller, there is no such sibling directory — the executable's
build step instead bundles log-collector's .py files as DATA alongside the
executable, extracted at runtime to PyInstaller's temporary
`sys._MEIPASS` directory (see agent/ubads_agent.spec). This module finds
`log-collector/` in the right place either way; log-collector's own code
is never modified or duplicated.
"""

from __future__ import annotations

import sys
from pathlib import Path

from paths import is_frozen

if is_frozen():
    # PyInstaller extracts bundled data files under sys._MEIPASS at
    # runtime (a fresh temporary directory per launch) — never a
    # persistent location, and never used for state (see paths.py).
    PROJECT_ROOT = Path(sys._MEIPASS)  # type: ignore[attr-defined]
else:
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
_LOG_COLLECTOR_DIR = PROJECT_ROOT / "log-collector"

if str(_LOG_COLLECTOR_DIR) not in sys.path:
    sys.path.insert(0, str(_LOG_COLLECTOR_DIR))

import collector  # noqa: E402  (log-collector's CLI module — reused for collect_events())
import event_parser  # noqa: E402
import validation  # noqa: E402

__all__ = ["collector", "event_parser", "validation", "PROJECT_ROOT"]
