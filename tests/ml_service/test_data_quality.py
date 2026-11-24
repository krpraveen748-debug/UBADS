"""
Tests for data_quality.py. Event/feature dicts below are DATA-QUALITY-TEST
FIXTURES ONLY, not real project data.
"""

from data_quality import generate_data_quality_report


def _event(user_sid, username, category, ts, computer_name="TEST-FIXTURE-PC"):
    return {
        "user_sid": user_sid,
        "username": username,
        "domain": "FIXTURE-DOMAIN",
        "event_category": category,
        "timestamp_utc": ts,
        "computer_name": computer_name,
    }


def test_report_counts_events_by_category_and_user():
    events = [
        _event("S-1", "alice", "authentication", "2026-03-05T09:00:00+00:00"),
        _event("S-1", "alice", "authentication", "2026-03-05T10:00:00+00:00"),
        _event("S-2", "bob", "file_activity", "2026-03-05T11:00:00+00:00"),
    ]
    report = generate_data_quality_report(events, [])
    assert report["total_events"] == 3
    assert report["events_by_category"]["authentication"] == 2
    assert report["events_by_category"]["file_activity"] == 1
    assert report["events_by_user"]["S-1"] == 2
    assert report["distinct_users"] == 2


def test_report_computes_coverage_period():
    events = [
        _event("S-1", "alice", "authentication", "2026-03-05T09:00:00+00:00"),
        _event("S-1", "alice", "authentication", "2026-03-06T09:00:00+00:00"),
    ]
    report = generate_data_quality_report(events, [])
    assert report["coverage_period"]["span_days"] == 1.0


def test_report_flags_missing_username():
    events = [_event(None, None, "authentication", "2026-03-05T09:00:00+00:00")]
    report = generate_data_quality_report(events, [])
    assert report["missing_username_count"] == 1


def test_report_warns_when_dataset_too_small():
    report = generate_data_quality_report([], [])
    assert report["total_events"] == 0
    assert any("total real event" in w for w in report["warnings"])


def test_report_no_warning_when_thresholds_met():
    events = [
        _event(f"S-{i}", f"user{i}", "authentication", "2026-03-05T09:00:00+00:00")
        for i in range(60)
    ]
    # Give one user enough events to cross the per-user threshold too.
    events += [
        _event("S-1", "user1", "authentication", "2026-03-05T10:00:00+00:00") for _ in range(25)
    ]
    feature_records = [{"user_id": "S-1"} for _ in range(5)]
    report = generate_data_quality_report(events, feature_records)
    assert "S-1" in report["users_with_enough_events_for_analysis"]
    assert "S-1" in report["users_with_enough_windows_for_baseline"]
