"""
Tests for baseline_stats.py. Feature-record dicts below are BASELINE-TEST
FIXTURES ONLY, not real project data.
"""

from baseline_stats import compute_user_baselines


def _record(total_activity_count, failed_login_count=0):
    return {
        "total_activity_count": total_activity_count,
        "successful_login_count": 5,
        "failed_login_count": failed_login_count,
        "login_failure_ratio": None,
        "file_activity_count": None,
        "files_accessed": None,
        "files_deleted": None,
        "process_count": None,
        "unique_process_count": None,
        "device_event_count": None,
        "download_related_event_count": None,
        "off_hours_activity_count": 1,
    }


def test_insufficient_data_below_min_windows():
    result = compute_user_baselines([_record(10), _record(12)], min_windows=3)
    assert result["insufficient_data"] is True
    assert result["window_count"] == 2


def test_sufficient_data_computes_stats():
    records = [_record(10), _record(20), _record(30)]
    result = compute_user_baselines(records, min_windows=3)
    assert result["insufficient_data"] is False
    stats = result["stats"]["total_activity_count"]
    assert stats["mean"] == 20
    assert stats["median"] == 20
    assert stats["min"] == 10
    assert stats["max"] == 30
    assert stats["n"] == 3


def test_feature_with_all_none_values_reports_insufficient_for_that_feature():
    records = [_record(10), _record(20), _record(30)]
    result = compute_user_baselines(records, min_windows=3)
    # file_activity_count is None in every record fixture above
    assert result["stats"]["file_activity_count"]["insufficient_data"] is True
    assert result["stats"]["file_activity_count"]["n"] == 0
