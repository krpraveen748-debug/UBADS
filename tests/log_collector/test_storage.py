"""
Unit tests for storage.py (the repository layer).

These tests use a private in-memory SQLite database created per test — they
never touch the real data/app.db. The normalized-event dicts below are
STORAGE-TEST FIXTURES ONLY, not real collected data.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from storage import (
    Base,
    EventRecord,
    build_event_uid,
    get_event_by_id,
    get_recent_events,
    insert_event,
    query_events,
)


def _normalized_event_fixture(event_record_id="1001", **overrides):
    base = {
        "event_id": 4624,
        "event_record_id": event_record_id,
        "event_type": "successful_logon",
        "event_category": "authentication",
        "timestamp": "2026-01-01T10:00:00.000000Z",
        "computer_name": "TEST-FIXTURE-PC",
        "username": "test.fixture.user",
        "domain": "FIXTURE-DOMAIN",
        "user_sid": "S-1-5-21-000000000-000000000-000000000-1001",
        "account_type": "human_or_unknown",
        "logon_type": 2,
        "logon_type_description": "interactive",
        "source_ip": None,
        "workstation_name": "TEST-FIXTURE-PC",
        "subject_username": None,
        "subject_domain": None,
        "failure_reason": None,
        "raw_event_data": {"LogonType": "2"},
    }
    base.update(overrides)
    return base


def _file_activity_event_fixture(event_record_id="2001", **overrides):
    base = {
        "event_id": 4663,
        "event_record_id": event_record_id,
        "event_type": "file_accessed",
        "event_category": "file_activity",
        "timestamp": "2026-01-01T11:00:00.000000Z",
        "computer_name": "TEST-FIXTURE-PC",
        "username": "test.fixture.user",
        "domain": "FIXTURE-DOMAIN",
        "user_sid": "S-1-5-21-000000000-000000000-000000000-1001",
        "account_type": "human_or_unknown",
        "file_path": r"C:\Users\test.fixture.user\Downloads\installer.exe",
        "file_extension": ".exe",
        "object_type": "File",
        "file_action": "accessed",
        "process_name": r"C:\Windows\explorer.exe",
        "access_list_raw": "%%4416",
        "raw_event_data": {"ObjectName": r"C:\Users\test.fixture.user\Downloads\installer.exe"},
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


def test_insert_event_inserts_new_record(session):
    outcome = insert_event(session, _normalized_event_fixture(), log_name="Security")
    assert outcome == "inserted"
    assert session.query(EventRecord).count() == 1


def test_insert_event_detects_duplicate_by_event_record_id(session):
    insert_event(session, _normalized_event_fixture(), log_name="Security")
    outcome = insert_event(session, _normalized_event_fixture(), log_name="Security")
    assert outcome == "duplicate"
    assert session.query(EventRecord).count() == 1


def test_different_event_record_id_is_treated_as_new(session):
    insert_event(session, _normalized_event_fixture(event_record_id="1001"), log_name="Security")
    outcome = insert_event(
        session, _normalized_event_fixture(event_record_id="1002"), log_name="Security"
    )
    assert outcome == "inserted"
    assert session.query(EventRecord).count() == 2


def test_running_collector_twice_does_not_duplicate_same_events(session):
    """Simulates the collector running twice over an overlapping window of
    real events: the second pass should skip everything already stored."""
    first_run_events = [
        _normalized_event_fixture(event_record_id="100"),
        _normalized_event_fixture(event_record_id="101"),
    ]
    second_run_events = [
        _normalized_event_fixture(event_record_id="101"),  # already stored
        _normalized_event_fixture(event_record_id="102"),  # new
    ]

    for event in first_run_events:
        insert_event(session, event, log_name="Security")

    outcomes = [insert_event(session, event, log_name="Security") for event in second_run_events]

    assert outcomes == ["duplicate", "inserted"]
    assert session.query(EventRecord).count() == 3


def test_get_recent_events_orders_newest_first(session):
    older = _normalized_event_fixture(event_record_id="1", timestamp="2026-01-01T09:00:00.000000Z")
    newer = _normalized_event_fixture(event_record_id="2", timestamp="2026-01-01T10:00:00.000000Z")
    insert_event(session, older, log_name="Security")
    insert_event(session, newer, log_name="Security")

    recent = get_recent_events(session, limit=1)
    assert len(recent) == 1
    assert recent[0].event_record_id == "2"


def test_build_event_uid_prefers_event_record_id():
    uid = build_event_uid("PC1", "Security", 42, 4624, "2026-01-01T10:00:00Z")
    assert uid == "PC1|Security|42"


def test_build_event_uid_falls_back_without_record_id():
    uid = build_event_uid("PC1", "Security", None, 4624, "2026-01-01T10:00:00Z")
    assert uid == "PC1|Security|fallback|4624|2026-01-01T10:00:00Z"


def test_insert_file_activity_event_stores_category_specific_columns(session):
    outcome = insert_event(session, _file_activity_event_fixture(), log_name="Security")
    assert outcome == "inserted"

    stored = session.query(EventRecord).one()
    assert stored.event_category == "file_activity"
    assert stored.file_path.endswith("installer.exe")
    assert stored.file_extension == ".exe"
    assert stored.file_action == "accessed"
    # Auth-only columns must stay empty for a non-auth event.
    assert stored.logon_type is None


def test_insert_download_related_event_uses_distinct_category(session):
    event = _file_activity_event_fixture(event_category="download_related")
    insert_event(session, event, log_name="Security")

    stored = session.query(EventRecord).one()
    assert stored.event_category == "download_related"
    # Still carries the underlying Windows event_type, not overwritten.
    assert stored.event_type == "file_accessed"


def test_get_recent_events_filters_by_category(session):
    insert_event(session, _normalized_event_fixture(event_record_id="1"), log_name="Security")
    insert_event(
        session, _file_activity_event_fixture(event_record_id="2"), log_name="Security"
    )

    auth_only = get_recent_events(session, limit=10, category="authentication")
    file_only = get_recent_events(session, limit=10, category="file_activity")

    assert len(auth_only) == 1
    assert auth_only[0].event_category == "authentication"
    assert len(file_only) == 1
    assert file_only[0].event_category == "file_activity"


def test_query_events_filters_by_category_and_username(session):
    insert_event(session, _normalized_event_fixture(event_record_id="1", username="alice"), log_name="Security")
    insert_event(session, _normalized_event_fixture(event_record_id="2", username="bob"), log_name="Security")
    insert_event(
        session, _file_activity_event_fixture(event_record_id="3", username="alice"), log_name="Security"
    )

    rows, total = query_events(session, category="authentication", username="alice")
    assert total == 1
    assert rows[0].username == "alice"
    assert rows[0].event_category == "authentication"


def test_query_events_filters_by_event_id(session):
    insert_event(session, _normalized_event_fixture(event_record_id="1"), log_name="Security")
    insert_event(
        session, _file_activity_event_fixture(event_record_id="2"), log_name="Security"
    )

    rows, total = query_events(session, event_id=4663)
    assert total == 1
    assert rows[0].event_id == 4663


def test_query_events_pagination(session):
    for i in range(5):
        insert_event(session, _normalized_event_fixture(event_record_id=str(i)), log_name="Security")

    page1, total = query_events(session, limit=2, offset=0)
    page2, _ = query_events(session, limit=2, offset=2)

    assert total == 5
    assert len(page1) == 2
    assert len(page2) == 2
    assert {r.event_record_id for r in page1}.isdisjoint({r.event_record_id for r in page2})


def test_query_events_filters_by_time_range(session):
    insert_event(
        session,
        _normalized_event_fixture(event_record_id="1", timestamp="2026-01-01T09:00:00.000000Z"),
        log_name="Security",
    )
    insert_event(
        session,
        _normalized_event_fixture(event_record_id="2", timestamp="2026-02-01T09:00:00.000000Z"),
        log_name="Security",
    )

    from datetime import datetime, timezone

    rows, total = query_events(
        session,
        start_time=datetime(2026, 1, 15, tzinfo=timezone.utc),
        end_time=datetime(2026, 2, 15, tzinfo=timezone.utc),
    )
    assert total == 1
    assert rows[0].event_record_id == "2"


def test_get_event_by_id_returns_record(session):
    insert_event(session, _normalized_event_fixture(event_record_id="1"), log_name="Security")
    stored = session.query(EventRecord).one()

    found = get_event_by_id(session, stored.id)
    assert found is not None
    assert found.id == stored.id


def test_get_event_by_id_returns_none_when_missing(session):
    assert get_event_by_id(session, 999999) is None
