"""
Time-window boundary logic for Phase 5 feature engineering.

Pure functions, no I/O — takes a UTC datetime and a window size, returns the
UTC window it falls into. Kept separate from feature_engineering.py so it
can be unit-tested and swapped independently (e.g. adding "weekly" later).

Window size choice: "daily" is the default. With the real, authorized data
volumes this project has collected so far (a handful to a few dozen events
per test run), hourly windows would mostly be empty or single-event,
carrying little statistical meaning; daily windows aggregate enough real
activity into each row to be interpretable while remaining fine-grained
enough to see day-to-day behavioral variation. "hourly" is fully supported
and selectable via --window-size for when more data volume exists.

Timestamps: window boundaries are computed in UTC, consistent with the
convention established in Phase 3 (validation.parse_utc_timestamp) — events
are stored with UTC timestamps, so windowing in UTC avoids any local-time
ambiguity, at the cost of window boundaries not necessarily lining up with
a specific user's local midnight/hour boundary. This is a known
simplification, documented here and in ml-service/FEATURES.md.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

VALID_WINDOW_SIZES = ("hourly", "daily")


def window_bounds(timestamp: datetime, window_size: str) -> tuple[datetime, datetime]:
    """Return (window_start, window_end) in UTC for the window `timestamp`
    falls into. window_end is exclusive (the start of the next window)."""
    if window_size not in VALID_WINDOW_SIZES:
        raise ValueError(f"window_size must be one of {VALID_WINDOW_SIZES}, got {window_size!r}")

    ts = timestamp.astimezone(timezone.utc)
    if window_size == "hourly":
        start = ts.replace(minute=0, second=0, microsecond=0)
        end = start + timedelta(hours=1)
    else:  # daily
        start = ts.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
    return start, end


def window_duration_hours(window_size: str) -> float:
    if window_size not in VALID_WINDOW_SIZES:
        raise ValueError(f"window_size must be one of {VALID_WINDOW_SIZES}, got {window_size!r}")
    return 1.0 if window_size == "hourly" else 24.0
