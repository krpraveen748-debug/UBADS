"""
Tests for collection_status.py. Event/feature dicts below are
COLLECTION-STATUS-TEST FIXTURES ONLY, not real project data.
"""

from collection_status import (
    MIN_ACTIVE_DAYS_FOR_RESEARCH,
    MIN_EVENTS_PER_CATEGORY_FOR_ANALYSIS,
    generate_collection_status,
)
from data_quality import MIN_EVENTS_PER_USER_FOR_ANALYSIS, MIN_TOTAL_EVENTS_FOR_ANALYSIS
from data_quality import MIN_WINDOWS_PER_USER_FOR_BASELINE as MIN_WINDOWS


def _auth_event(user_sid, day, account_type="human_or_unknown", computer="TEST-FIXTURE-PC"):
    return {
        "event_id": 4624,
        "event_category": "authentication",
        "event_type": "successful_logon",
        "user_sid": user_sid,
        "username": "test.fixture.user",
        "domain": "FIXTURE-DOMAIN",
        "account_type": account_type,
        "computer_name": computer,
        "timestamp_utc": f"2026-03-{day:02d}T09:00:00+00:00",
    }


def test_empty_database_is_insufficient_on_both_axes():
    status = generate_collection_status([], [], window_size="daily")
    assert status["decision"] == "INSUFFICIENT_REAL_DATA"
    assert status["technical_sufficiency"]["is_sufficient"] is False
    assert status["research_sufficiency"]["is_sufficient"] is False
    assert "No events stored" in status["technical_sufficiency"]["reasons"][0]


def test_technical_sufficiency_true_with_events_and_one_feature_window():
    events = [_auth_event("S-1", 5)]
    feature_records = [{"user_id": "S-1", "window_size": "daily", "successful_login_count": 1}]
    status = generate_collection_status(events, feature_records, window_size="daily")
    assert status["technical_sufficiency"]["is_sufficient"] is True
    # But research sufficiency still fails with only one event/window.
    assert status["research_sufficiency"]["is_sufficient"] is False
    assert status["decision"] == "INSUFFICIENT_REAL_DATA"


def test_service_accounts_excluded_from_human_candidates():
    events = [_auth_event("S-1-5-18", day=d, account_type="system") for d in range(1, 30)]
    feature_records = [
        {"user_id": "S-1-5-18", "window_size": "daily", "successful_login_count": 1} for _ in range(10)
    ]
    status = generate_collection_status(events, feature_records, window_size="daily")
    assert status["research_sufficiency"]["qualifying_users"] == []
    assert any("human" in r for r in status["research_sufficiency"]["reasons"])


def test_ready_for_ml_when_all_research_criteria_met():
    # One human user with enough events, enough categorized events overall,
    # enough active days, and enough behavioral windows. 20 days x 3
    # events/day comfortably clears every current threshold (50 total, 20
    # per-user, 3 windows, 3 active days) with margin to spare.
    per_day_events = 3
    days_count = 20
    events = []
    feature_records = []
    for day in range(1, days_count + 1):
        for _ in range(per_day_events):
            events.append(_auth_event("S-1-HUMAN", day))
        feature_records.append(
            {"user_id": "S-1-HUMAN", "window_size": "daily", "successful_login_count": per_day_events}
        )

    assert len(events) >= MIN_EVENTS_PER_USER_FOR_ANALYSIS
    assert len(events) >= MIN_TOTAL_EVENTS_FOR_ANALYSIS
    assert len(feature_records) >= MIN_WINDOWS
    assert days_count >= MIN_ACTIVE_DAYS_FOR_RESEARCH

    status = generate_collection_status(events, feature_records, window_size="daily")
    assert status["research_sufficiency"]["is_sufficient"] is True
    assert "S-1-HUMAN" in status["research_sufficiency"]["qualifying_users"]
    assert status["decision"] == "READY_FOR_ML"


def test_event_coverage_reports_per_category_counts_and_sufficiency():
    events = [_auth_event("S-1", d) for d in range(1, MIN_EVENTS_PER_CATEGORY_FOR_ANALYSIS + 2)]
    status = generate_collection_status(events, [], window_size="daily")
    auth_coverage = status["event_coverage"]["authentication"]
    assert auth_coverage["event_count"] == len(events)
    assert auth_coverage["has_sufficient_data"] is True
    assert status["event_coverage"]["file_activity"]["event_count"] == 0
    assert status["event_coverage"]["file_activity"]["has_sufficient_data"] is False


def test_user_coverage_reports_active_days_and_span():
    events = [_auth_event("S-1", 5), _auth_event("S-1", 6), _auth_event("S-1", 7)]
    status = generate_collection_status(events, [], window_size="daily")
    coverage = status["user_coverage"]["S-1"]
    assert coverage["events_count"] == 3
    assert coverage["active_days"] == 3
    assert coverage["span_days"] == 2.0


def test_basic_inspection_lists_distinct_event_ids_and_computers():
    events = [_auth_event("S-1", 5, computer="PC-A"), _auth_event("S-2", 5, computer="PC-B")]
    status = generate_collection_status(events, [], window_size="daily")
    assert status["basic_inspection"]["distinct_event_ids"] == [4624]
    assert status["basic_inspection"]["distinct_computers"] == ["PC-A", "PC-B"]
    assert status["basic_inspection"]["distinct_users"] == 2
