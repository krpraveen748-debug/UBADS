"""
Per-user baseline descriptive statistics over stored behavior_features rows.

This is NOT anomaly detection or modeling — no thresholds, scores, or
model fitting happen here. It only computes plain descriptive statistics
(mean/median/stdev/min/max) per user per numeric feature, from that user's
REAL stored feature-window history, as the documented foundation for
Phase 6. Insufficient history is reported explicitly rather than silently
producing a baseline from too little data.
"""

from __future__ import annotations

import statistics

MIN_WINDOWS_FOR_BASELINE = 3

# Only numeric features where a per-user baseline is meaningful; identifiers
# and window boundaries are excluded.
_BASELINE_FEATURES = [
    "total_activity_count",
    "successful_login_count",
    "failed_login_count",
    "login_failure_ratio",
    "file_activity_count",
    "files_accessed",
    "files_deleted",
    "process_count",
    "unique_process_count",
    "device_event_count",
    "download_related_event_count",
    "off_hours_activity_count",
]


def compute_user_baselines(feature_records: list[dict], min_windows: int = MIN_WINDOWS_FOR_BASELINE) -> dict:
    """feature_records: all behavior_features rows for ONE user (any window
    size — caller should pass records for a single window_size to keep
    units comparable). Returns a dict with `window_count`, and either
    `insufficient_data: True` (if window_count < min_windows) or a `stats`
    dict of {feature_name: {mean, median, stdev, min, max, n}} — computed
    only over windows where that feature is non-None (so a feature only
    available in some windows still gets a real baseline over the windows
    where it was actually observed).
    """
    window_count = len(feature_records)
    if window_count < min_windows:
        return {
            "window_count": window_count,
            "insufficient_data": True,
            "reason": (
                f"Only {window_count} time window(s) of real data available; "
                f"at least {min_windows} are required for a meaningful baseline."
            ),
        }

    stats: dict[str, dict] = {}
    for feature_name in _BASELINE_FEATURES:
        values = [r[feature_name] for r in feature_records if r.get(feature_name) is not None]
        if len(values) < min_windows:
            stats[feature_name] = {
                "insufficient_data": True,
                "n": len(values),
                "reason": (
                    f"Only {len(values)} window(s) had a non-null value for "
                    f"this feature; at least {min_windows} are required."
                ),
            }
            continue
        stats[feature_name] = {
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
            "min": min(values),
            "max": max(values),
            "n": len(values),
        }

    return {
        "window_count": window_count,
        "insufficient_data": False,
        "stats": stats,
    }
