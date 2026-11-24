"""
Tests for the Phase 5 behavior_features repository functions in storage.py.
Uses a private in-memory SQLite database (never the real data/app.db).
Feature-record dicts below are STORAGE-TEST FIXTURES ONLY, not real data.
"""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from storage import Base, BehaviorFeature, feature_record_to_dict, get_feature_records, save_feature_record


def _feature_record(user_id="S-1", window_start=None, **overrides):
    window_start = window_start or datetime(2026, 3, 5, 0, 0, 0, tzinfo=timezone.utc)
    base = {
        "user_id": user_id,
        "username": "test.fixture.user",
        "domain": "FIXTURE-DOMAIN",
        "account_type": "human_or_unknown",
        "window_size": "daily",
        "window_start": window_start,
        "window_end": datetime(2026, 3, 6, 0, 0, 0, tzinfo=timezone.utc),
        "total_activity_count": 5,
        "number_of_categories_active": 1,
        "day_of_week": 3,
        "is_weekend": 0,
        "off_hours_activity_count": 0,
        "distinct_active_hours": 2,
        "successful_login_count": 3,
        "failed_login_count": 0,
        "login_failure_ratio": None,
        "unique_login_hours": 2,
        "first_login_hour": 9,
        "last_login_hour": 10,
        "average_login_hour": 9.5,
        "logoff_count": 1,
        "files_accessed": None,
        "files_deleted": None,
        "files_handle_requested": None,
        "unique_file_extensions": None,
        "unique_directories": None,
        "file_activity_count": None,
        "process_count": None,
        "unique_process_count": None,
        "process_activity_frequency": None,
        "device_event_count": None,
        "unique_devices": None,
        "new_device_count": None,
        "download_related_event_count": None,
        "download_related_file_count": None,
        "download_related_activity_frequency": None,
        "authentication_to_file_activity_ratio": None,
        "authentication_to_process_activity_ratio": None,
        "activity_after_failed_login_count": None,
        "avg_files_per_session": None,
    }
    base.update(overrides)
    return base


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(bind=engine)()
    try:
        yield db
    finally:
        db.close()


def test_save_feature_record_inserts_new_row(session):
    outcome = save_feature_record(session, _feature_record())
    assert outcome == "inserted"
    assert session.query(BehaviorFeature).count() == 1


def test_save_feature_record_upserts_same_window(session):
    save_feature_record(session, _feature_record(total_activity_count=5))
    outcome = save_feature_record(session, _feature_record(total_activity_count=9))
    assert outcome == "updated"
    assert session.query(BehaviorFeature).count() == 1
    stored = session.query(BehaviorFeature).one()
    assert stored.total_activity_count == 9  # recomputed value replaced the old one


def test_save_feature_record_different_window_is_separate_row(session):
    save_feature_record(session, _feature_record(window_start=datetime(2026, 3, 5, tzinfo=timezone.utc)))
    save_feature_record(session, _feature_record(window_start=datetime(2026, 3, 6, tzinfo=timezone.utc)))
    assert session.query(BehaviorFeature).count() == 2


def test_get_feature_records_filters_by_user(session):
    save_feature_record(session, _feature_record(user_id="S-1"))
    save_feature_record(session, _feature_record(user_id="S-2"))

    only_s1 = get_feature_records(session, user_id="S-1", limit=10)
    assert len(only_s1) == 1
    assert only_s1[0].user_id == "S-1"


def test_feature_record_to_dict_round_trips_null_and_real_values(session):
    save_feature_record(session, _feature_record())
    record = get_feature_records(session, limit=1)[0]
    result = feature_record_to_dict(record)
    assert result["successful_login_count"] == 3
    assert result["file_activity_count"] is None  # category never observed
