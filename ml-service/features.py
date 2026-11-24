"""
Behavioral feature calculations — pure functions, no database access.

Every function here takes a list of normalized event dicts (the exact
shape storage.event_record_to_dict() produces — reused as-is, not
reinvented) already filtered to one user's events within one time window,
and returns a dict of computed feature values.

Core rule, applied everywhere in this module: a feature is only computed
when the underlying event data actually supports it. Where a count would
be zero because no matching events exist IN THIS WINDOW (but the category
has been observed elsewhere in the dataset), the result is a real 0 — not
None. Whether a whole category is even attempted at all (vs. left `None`
because it has never once appeared anywhere in the database) is decided
by the caller (feature_engineering.py), which passes in `category_available`
flags computed once from the full event history — this module never makes
that decision itself. See ml-service/FEATURES.md for the full rule set.

Known, documented scope limits (see ml-service/README.md "Known
limitations" for the full list):
  - file_action granularity is coarse (handle_requested/accessed/deleted
    only) — this project cannot reliably distinguish created vs modified,
    per Phase 4's documented limitation, so those are NOT computed here.
  - "off-hours" uses UTC hour boundaries, not each user's true local time
    (which isn't reliably known) — an approximation, not a precise signal.
  - Session-based features (activity_after_failed_login_count,
    avg_files_per_session) only look WITHIN the current window; activity
    that crosses a window boundary (e.g. a failed login at 23:58 followed
    by file access at 00:02 the next day) is not linked. Documented rather
    than silently handled.
"""

from __future__ import annotations

import os
import statistics
from datetime import datetime, timezone

from windowing import window_duration_hours

OFF_HOURS_START_UTC = 9  # inclusive
OFF_HOURS_END_UTC = 17  # exclusive — [9, 17) UTC is treated as "business hours"
SESSION_FOLLOW_UP_SECONDS = 300  # 5 minutes, for activity_after_failed_login_count


def _event_hour_utc(event: dict) -> int | None:
    ts = event.get("timestamp_utc")
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts).astimezone(timezone.utc).hour
    except ValueError:
        return None


def compute_time_features(events: list[dict], window_start: datetime) -> dict:
    """Always computable — timestamp is a required field for every stored
    event, so this needs no category-availability check."""
    hours = [h for h in (_event_hour_utc(e) for e in events) if h is not None]
    off_hours_count = sum(1 for h in hours if h < OFF_HOURS_START_UTC or h >= OFF_HOURS_END_UTC)
    return {
        "day_of_week": window_start.weekday(),  # 0=Monday .. 6=Sunday
        "is_weekend": 1 if window_start.weekday() >= 5 else 0,
        "off_hours_activity_count": off_hours_count,
        "distinct_active_hours": len(set(hours)),
    }


def compute_authentication_features(events: list[dict]) -> dict:
    """"Login events" for hour-based stats means successful_logon +
    failed_logon (both represent a real logon attempt at a specific time);
    logoff_count is tracked separately."""
    auth_events = [e for e in events if e.get("event_category") == "authentication"]
    successful = [e for e in auth_events if e.get("event_type") == "successful_logon"]
    failed = [e for e in auth_events if e.get("event_type") == "failed_logon"]
    logoffs = [e for e in auth_events if e.get("event_type") in ("logoff", "user_initiated_logoff")]

    total_attempts = len(successful) + len(failed)
    login_hours = [h for h in (_event_hour_utc(e) for e in successful + failed) if h is not None]

    return {
        "successful_login_count": len(successful),
        "failed_login_count": len(failed),
        "login_failure_ratio": (len(failed) / total_attempts) if total_attempts > 0 else None,
        "unique_login_hours": len(set(login_hours)),
        "first_login_hour": min(login_hours) if login_hours else None,
        "last_login_hour": max(login_hours) if login_hours else None,
        "average_login_hour": statistics.mean(login_hours) if login_hours else None,
        "logoff_count": len(logoffs),
    }


def compute_file_activity_features(events: list[dict]) -> dict:
    """Includes rows classified as download_related too, since those still
    carry file_action/file_path — anything with file_action populated is
    file activity at the mechanism level. See download-related features for
    the download-specific subset."""
    file_events = [e for e in events if e.get("file_action")]
    extensions = {e["file_extension"] for e in file_events if e.get("file_extension")}
    directories = {
        os.path.dirname(e["file_path"]) for e in file_events if e.get("file_path")
    }
    return {
        "files_accessed": sum(1 for e in file_events if e.get("file_action") == "accessed"),
        "files_deleted": sum(1 for e in file_events if e.get("file_action") == "deleted"),
        "files_handle_requested": sum(
            1 for e in file_events if e.get("file_action") == "handle_requested"
        ),
        "unique_file_extensions": len(extensions),
        "unique_directories": len(directories),
        "file_activity_count": len(file_events),
    }


def compute_process_activity_features(events: list[dict], window_size: str) -> dict:
    process_events = [e for e in events if e.get("event_category") == "process_activity"]
    names = {e["process_name"] for e in process_events if e.get("process_name")}
    duration = window_duration_hours(window_size)
    return {
        "process_count": len(process_events),
        "unique_process_count": len(names),
        "process_activity_frequency": len(process_events) / duration if duration else None,
    }


def compute_device_activity_features(events: list[dict], seen_device_ids_before: set) -> dict:
    """`seen_device_ids_before` is the set of device identifiers already
    observed for this user in any EARLIER window (caller maintains this,
    processing windows in chronological order) — a device is "new" only
    the first time it's ever seen for that user across the real stored
    history, never guessed."""
    device_events = [e for e in events if e.get("event_category") == "device_activity"]
    device_keys = {
        (e.get("device_id") or e.get("device_description"))
        for e in device_events
        if e.get("device_id") or e.get("device_description")
    }
    new_devices = device_keys - seen_device_ids_before
    return {
        "device_event_count": len(device_events),
        "unique_devices": len(device_keys),
        "new_device_count": len(new_devices),
    }, device_keys


def compute_download_related_features(events: list[dict], window_size: str) -> dict:
    download_events = [e for e in events if e.get("event_category") == "download_related"]
    unique_files = {e["file_path"] for e in download_events if e.get("file_path")}
    duration = window_duration_hours(window_size)
    return {
        "download_related_event_count": len(download_events),
        "download_related_file_count": len(unique_files),
        "download_related_activity_frequency": (
            len(download_events) / duration if duration else None
        ),
    }


def compute_activity_after_failed_login_count(events: list[dict]) -> int:
    """Count of non-authentication events occurring within
    SESSION_FOLLOW_UP_SECONDS after any failed_logon event for this user,
    WITHIN THIS WINDOW ONLY (see module docstring limitation)."""
    failed_logon_times = []
    for e in events:
        if e.get("event_type") == "failed_logon" and e.get("timestamp_utc"):
            try:
                failed_logon_times.append(datetime.fromisoformat(e["timestamp_utc"]))
            except ValueError:
                continue
    if not failed_logon_times:
        return 0

    count = 0
    for e in events:
        if e.get("event_category") == "authentication" or not e.get("timestamp_utc"):
            continue
        try:
            ts = datetime.fromisoformat(e["timestamp_utc"])
        except ValueError:
            continue
        for failed_ts in failed_logon_times:
            delta = (ts - failed_ts).total_seconds()
            if 0 <= delta <= SESSION_FOLLOW_UP_SECONDS:
                count += 1
                break
    return count


def compute_avg_files_per_session(events: list[dict]) -> float | None:
    """Approximate session = from a successful_logon to the next
    logoff/user_initiated_logoff OR the next successful_logon for the same
    user, whichever comes first, WITHIN THIS WINDOW ONLY. Sessions with no
    observed end in this window are excluded (an unbounded/open session
    would overcount or undercount file activity in a misleading way)."""
    timed_events = []
    for e in events:
        if not e.get("timestamp_utc"):
            continue
        try:
            ts = datetime.fromisoformat(e["timestamp_utc"])
        except ValueError:
            continue
        timed_events.append((ts, e))
    timed_events.sort(key=lambda pair: pair[0])

    session_file_counts = []
    open_session_start = None
    file_count_in_session = 0

    for ts, e in timed_events:
        event_type = e.get("event_type")
        if event_type == "successful_logon":
            if open_session_start is not None:
                # A new logon before the previous session closed — the
                # previous session has no observed end; discard it rather
                # than guess where it ended.
                pass
            open_session_start = ts
            file_count_in_session = 0
        elif event_type in ("logoff", "user_initiated_logoff") and open_session_start is not None:
            session_file_counts.append(file_count_in_session)
            open_session_start = None
            file_count_in_session = 0
        elif open_session_start is not None and e.get("file_action"):
            file_count_in_session += 1

    if not session_file_counts:
        return None
    return statistics.mean(session_file_counts)


def compute_cross_category_features(
    events: list[dict],
    category_availability: dict[str, bool],
    auth_features: dict,
    file_features: dict,
    process_features: dict,
) -> dict:
    categories_present = {
        e["event_category"]
        for e in events
        if e.get("event_category") and e["event_category"] != "uncategorized"
    }

    auth_total = None
    if category_availability.get("authentication"):
        auth_total = (auth_features.get("successful_login_count") or 0) + (
            auth_features.get("failed_login_count") or 0
        )

    auth_to_file_ratio = None
    if (
        category_availability.get("authentication")
        and category_availability.get("file_activity")
        and file_features.get("file_activity_count")
    ):
        auth_to_file_ratio = auth_total / file_features["file_activity_count"]

    auth_to_process_ratio = None
    if (
        category_availability.get("authentication")
        and category_availability.get("process_activity")
        and process_features.get("process_count")
    ):
        auth_to_process_ratio = auth_total / process_features["process_count"]

    return {
        "total_activity_count": len(events),
        "number_of_categories_active": len(categories_present),
        "authentication_to_file_activity_ratio": auth_to_file_ratio,
        "authentication_to_process_activity_ratio": auth_to_process_ratio,
        "activity_after_failed_login_count": (
            compute_activity_after_failed_login_count(events)
            if category_availability.get("authentication")
            else None
        ),
        "avg_files_per_session": (
            compute_avg_files_per_session(events)
            if category_availability.get("authentication") and category_availability.get("file_activity")
            else None
        ),
    }
