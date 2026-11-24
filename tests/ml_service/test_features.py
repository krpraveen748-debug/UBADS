"""
Unit tests for features.py. The event dicts below are FEATURE-ENGINEERING
TEST FIXTURES ONLY — hand-written dicts shaped like storage.event_record_to_dict()
output, used to exercise the calculation logic. They are NOT real collected
data and do not represent any real user or machine.
"""

from datetime import datetime, timezone

from features import (
    compute_activity_after_failed_login_count,
    compute_authentication_features,
    compute_avg_files_per_session,
    compute_cross_category_features,
    compute_device_activity_features,
    compute_download_related_features,
    compute_file_activity_features,
    compute_process_activity_features,
    compute_time_features,
)


def _event(event_category, event_type, hour, minute=0, **overrides):
    ts = datetime(2026, 3, 5, hour, minute, 0, tzinfo=timezone.utc).isoformat()
    base = {
        "event_category": event_category,
        "event_type": event_type,
        "timestamp_utc": ts,
        "username": "test.fixture.user",
        "domain": "FIXTURE-DOMAIN",
        "account_type": "human_or_unknown",
    }
    base.update(overrides)
    return base


def test_compute_time_features_weekday():
    window_start = datetime(2026, 3, 5, 0, 0, 0, tzinfo=timezone.utc)  # Thursday
    events = [_event("authentication", "successful_logon", 10), _event("authentication", "successful_logon", 20)]
    result = compute_time_features(events, window_start)
    assert result["day_of_week"] == 3  # Thursday
    assert result["is_weekend"] == 0
    assert result["off_hours_activity_count"] == 1  # only the hour=20 event is off-hours
    assert result["distinct_active_hours"] == 2


def test_compute_time_features_weekend():
    window_start = datetime(2026, 3, 7, 0, 0, 0, tzinfo=timezone.utc)  # Saturday
    result = compute_time_features([], window_start)
    assert result["is_weekend"] == 1
    assert result["distinct_active_hours"] == 0


def test_compute_authentication_features_basic():
    events = [
        _event("authentication", "successful_logon", 9),
        _event("authentication", "successful_logon", 10),
        _event("authentication", "failed_logon", 10),
        _event("authentication", "logoff", 12),
    ]
    result = compute_authentication_features(events)
    assert result["successful_login_count"] == 2
    assert result["failed_login_count"] == 1
    assert result["login_failure_ratio"] == 1 / 3
    assert result["unique_login_hours"] == 2
    assert result["first_login_hour"] == 9
    assert result["last_login_hour"] == 10
    assert result["logoff_count"] == 1


def test_compute_authentication_features_no_attempts_gives_none_ratio():
    result = compute_authentication_features([_event("authentication", "logoff", 12)])
    assert result["successful_login_count"] == 0
    assert result["failed_login_count"] == 0
    assert result["login_failure_ratio"] is None  # undefined, not zero


def test_compute_file_activity_features():
    events = [
        _event("file_activity", "file_accessed", 9, file_action="accessed", file_path=r"C:\a\b.pdf", file_extension=".pdf"),
        _event("file_activity", "file_deleted", 10, file_action="deleted", file_path=r"C:\a\c.txt", file_extension=".txt"),
        _event("download_related", "file_accessed", 11, file_action="accessed", file_path=r"C:\Downloads\d.exe", file_extension=".exe"),
    ]
    result = compute_file_activity_features(events)
    assert result["files_accessed"] == 2  # includes the download_related row
    assert result["files_deleted"] == 1
    assert result["unique_file_extensions"] == 3
    assert result["unique_directories"] == 2
    assert result["file_activity_count"] == 3


def test_compute_process_activity_features():
    events = [
        _event("process_activity", "process_created", 9, process_name="notepad.exe"),
        _event("process_activity", "process_created", 10, process_name="notepad.exe"),
        _event("process_activity", "process_created", 11, process_name="cmd.exe"),
    ]
    result = compute_process_activity_features(events, "daily")
    assert result["process_count"] == 3
    assert result["unique_process_count"] == 2
    assert result["process_activity_frequency"] == 3 / 24


def test_compute_device_activity_features_marks_new_device_once():
    events = [_event("device_activity", "device_recognized", 9, device_id="USB1")]
    seen_before = set()
    result, new_keys = compute_device_activity_features(events, seen_before)
    assert result["device_event_count"] == 1
    assert result["unique_devices"] == 1
    assert result["new_device_count"] == 1
    assert new_keys == {"USB1"}

    # Same device seen again in a later window (caller updates seen_before)
    seen_before |= new_keys
    result2, _ = compute_device_activity_features(events, seen_before)
    assert result2["new_device_count"] == 0


def test_compute_download_related_features():
    events = [
        _event("download_related", "file_accessed", 9, file_path=r"C:\Downloads\a.exe"),
        _event("download_related", "file_accessed", 10, file_path=r"C:\Downloads\a.exe"),
        _event("download_related", "file_deleted", 11, file_path=r"C:\Downloads\b.zip"),
    ]
    result = compute_download_related_features(events, "daily")
    assert result["download_related_event_count"] == 3
    assert result["download_related_file_count"] == 2  # distinct file paths


def test_compute_activity_after_failed_login_count():
    events = [
        _event("authentication", "failed_logon", 9, minute=0),
        _event("process_activity", "process_created", 9, minute=2, process_name="cmd.exe"),  # within 5 min
        _event("file_activity", "file_accessed", 9, minute=30, file_action="accessed"),  # too late
    ]
    assert compute_activity_after_failed_login_count(events) == 1


def test_compute_avg_files_per_session():
    events = [
        _event("authentication", "successful_logon", 9, minute=0),
        _event("file_activity", "file_accessed", 9, minute=5, file_action="accessed"),
        _event("file_activity", "file_accessed", 9, minute=10, file_action="accessed"),
        _event("authentication", "logoff", 9, minute=15),
    ]
    assert compute_avg_files_per_session(events) == 2.0


def test_compute_avg_files_per_session_excludes_unclosed_session():
    events = [
        _event("authentication", "successful_logon", 9, minute=0),
        _event("file_activity", "file_accessed", 9, minute=5, file_action="accessed"),
        # no logoff — session never closes in this window
    ]
    assert compute_avg_files_per_session(events) is None


def test_compute_cross_category_features_ratios_and_counts():
    events = [
        _event("authentication", "successful_logon", 9),
        _event("authentication", "failed_logon", 9, minute=1),
        _event("file_activity", "file_accessed", 10, file_action="accessed"),
    ]
    availability = {
        "authentication": True,
        "file_activity": True,
        "process_activity": False,
        "device_activity": False,
        "download_related": False,
    }
    auth_features = compute_authentication_features(events)
    file_features = compute_file_activity_features(events)
    process_features = {"process_count": None, "unique_process_count": None, "process_activity_frequency": None}

    result = compute_cross_category_features(events, availability, auth_features, file_features, process_features)
    assert result["total_activity_count"] == 3
    assert result["number_of_categories_active"] == 2
    assert result["authentication_to_file_activity_ratio"] == 2 / 1
    assert result["authentication_to_process_activity_ratio"] is None  # process_activity unavailable


def test_compute_cross_category_features_ratio_none_when_denominator_zero():
    events = [_event("authentication", "successful_logon", 9)]
    availability = {
        "authentication": True,
        "file_activity": True,
        "process_activity": True,
        "device_activity": False,
        "download_related": False,
    }
    auth_features = compute_authentication_features(events)
    file_features = {
        "files_accessed": 0,
        "files_deleted": 0,
        "files_handle_requested": 0,
        "unique_file_extensions": 0,
        "unique_directories": 0,
        "file_activity_count": 0,
    }
    process_features = {"process_count": 0, "unique_process_count": 0, "process_activity_frequency": 0.0}

    result = compute_cross_category_features(events, availability, auth_features, file_features, process_features)
    assert result["authentication_to_file_activity_ratio"] is None
    assert result["authentication_to_process_activity_ratio"] is None
