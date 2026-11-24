"""
Tests for feature_engineering.py's pure orchestration logic (grouping,
category availability, per-window record assembly) — no database access.
Importing feature_engineering.py creates (but does not open/write to) the
same SQLAlchemy engine storage.py always creates on import; these tests
never call init_db()/save_feature_record(), so the real data/app.db file is
never touched.

Event dicts below are FEATURE-ENGINEERING TEST FIXTURES ONLY, not real data.
"""

from datetime import datetime, timezone

from feature_engineering import (
    compute_category_availability,
    compute_feature_record,
    group_events_by_user_and_window,
)
from windowing import window_bounds


def _event(user_sid, category, event_type, timestamp, **overrides):
    base = {
        "user_sid": user_sid,
        "username": "test.fixture.user",
        "domain": "FIXTURE-DOMAIN",
        "account_type": "human_or_unknown",
        "event_category": category,
        "event_type": event_type,
        "timestamp_utc": timestamp,
    }
    base.update(overrides)
    return base


def test_compute_category_availability_reflects_whats_actually_present():
    events = [
        _event("S-1", "authentication", "successful_logon", "2026-03-05T09:00:00+00:00"),
    ]
    availability = compute_category_availability(events)
    assert availability["authentication"] is True
    assert availability["file_activity"] is False
    assert availability["process_activity"] is False
    assert availability["device_activity"] is False
    assert availability["download_related"] is False


def test_group_events_by_user_and_window_separates_users_and_days():
    events = [
        _event("S-1", "authentication", "successful_logon", "2026-03-05T09:00:00+00:00"),
        _event("S-1", "authentication", "successful_logon", "2026-03-06T09:00:00+00:00"),
        _event("S-2", "authentication", "successful_logon", "2026-03-05T09:00:00+00:00"),
    ]
    grouped = group_events_by_user_and_window(events, "daily")
    assert set(grouped.keys()) == {"S-1", "S-2"}
    assert len(grouped["S-1"]) == 2  # two different days
    assert len(grouped["S-2"]) == 1


def test_group_events_skips_events_with_no_timestamp():
    events = [_event("S-1", "authentication", "successful_logon", None)]
    grouped = group_events_by_user_and_window(events, "daily")
    assert grouped == {}


def test_compute_feature_record_marks_unavailable_categories_as_none():
    window_start = datetime(2026, 3, 5, 0, 0, 0, tzinfo=timezone.utc)
    _, window_end = window_bounds(window_start, "daily")
    events = [_event("S-1", "authentication", "successful_logon", "2026-03-05T09:00:00+00:00")]
    availability = compute_category_availability(events)

    record = compute_feature_record("S-1", window_start, window_end, "daily", events, availability)

    assert record["successful_login_count"] == 1
    # file_activity was never observed anywhere -> None, not 0
    assert record["file_activity_count"] is None
    assert record["process_count"] is None


def test_compute_feature_record_real_zero_when_category_available_but_absent_this_window():
    window_start = datetime(2026, 3, 5, 0, 0, 0, tzinfo=timezone.utc)
    _, window_end = window_bounds(window_start, "daily")
    # file_activity IS observed somewhere in the dataset overall...
    all_events = [
        _event("S-1", "authentication", "successful_logon", "2026-03-05T09:00:00+00:00"),
        _event("S-1", "file_activity", "file_accessed", "2026-03-06T09:00:00+00:00", file_action="accessed"),
    ]
    availability = compute_category_availability(all_events)
    # ...but THIS window only has the authentication event.
    events_in_window = [all_events[0]]

    record = compute_feature_record("S-1", window_start, window_end, "daily", events_in_window, availability)
    assert record["file_activity_count"] == 0  # real zero, category is known to be collected
