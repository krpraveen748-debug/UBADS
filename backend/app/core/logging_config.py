"""
Structured application logging setup.

Call `configure_logging()` once, at app startup (see main.py). Everything
in this app should log via `logging.getLogger(__name__)`, never `print()`,
so log level/format is controlled in exactly one place.

What gets logged (by convention, enforced by code review, not by a
runtime filter — there is no sensitive payload flowing through this
backend to begin with, since it only ever reads already-normalized,
already-privacy-reviewed data from log-collector/ml-service):
  - startup/shutdown, CORS configuration used, DB connectivity checks
  - unhandled exceptions (full detail server-side; see core/errors.py for
    what's ever returned to a client)
  - agent-authentication failures (see security/agent_auth.py) — logs
    THAT a request was rejected and why (missing/invalid key), never the
    key value itself
  - service/database failures surfaced as 503s

What must NEVER be logged, matching this project's privacy boundary since
Phase 2: passwords, password hashes, keystrokes, screenshots, webcam/mic
data, private messages, browser passwords/cookies, document contents, raw
`raw_event_data` blobs, or full agent API key values.
"""

from __future__ import annotations

import logging
import sys


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.setLevel(level.upper())

    # Idempotent — configure_logging() may run more than once under a
    # process supervisor/reload; don't stack duplicate handlers.
    if any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        return

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    root.addHandler(handler)
