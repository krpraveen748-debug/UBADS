from datetime import datetime, timezone

import pytest
from windowing import window_bounds, window_duration_hours


def test_daily_window_truncates_to_midnight_utc():
    ts = datetime(2026, 3, 5, 14, 32, 10, tzinfo=timezone.utc)
    start, end = window_bounds(ts, "daily")
    assert start == datetime(2026, 3, 5, 0, 0, 0, tzinfo=timezone.utc)
    assert end == datetime(2026, 3, 6, 0, 0, 0, tzinfo=timezone.utc)


def test_hourly_window_truncates_to_the_hour():
    ts = datetime(2026, 3, 5, 14, 32, 10, tzinfo=timezone.utc)
    start, end = window_bounds(ts, "hourly")
    assert start == datetime(2026, 3, 5, 14, 0, 0, tzinfo=timezone.utc)
    assert end == datetime(2026, 3, 5, 15, 0, 0, tzinfo=timezone.utc)


def test_window_bounds_rejects_invalid_size():
    with pytest.raises(ValueError):
        window_bounds(datetime.now(timezone.utc), "weekly")


def test_window_duration_hours():
    assert window_duration_hours("hourly") == 1.0
    assert window_duration_hours("daily") == 24.0
