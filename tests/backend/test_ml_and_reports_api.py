"""
Tests for GET /api/ml/collection-status and GET /api/reports/data-quality.
Uses only the isolated in-memory test database (see conftest.py).
"""

from tests.backend.conftest import insert_fixture_event


def test_collection_status_on_empty_database_is_insufficient(client):
    response = client.get("/api/ml/collection-status")
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "INSUFFICIENT_REAL_DATA"
    assert body["technical_sufficiency"]["is_sufficient"] is False
    assert "human_candidate_account_count" in body


def test_collection_status_never_reports_ready_on_thin_fixture_data(client, test_session):
    insert_fixture_event(test_session)
    response = client.get("/api/ml/collection-status")
    body = response.json()
    # One fixture event is nowhere near the real research-sufficiency bar —
    # this must stay honest, not flip to READY_FOR_ML.
    assert body["decision"] == "INSUFFICIENT_REAL_DATA"


def test_data_quality_report_reflects_real_counts(client, test_session):
    insert_fixture_event(test_session, event_record_id="1")
    insert_fixture_event(test_session, event_record_id="2")

    response = client.get("/api/reports/data-quality")
    assert response.status_code == 200
    body = response.json()
    assert body["total_events"] == 2
    assert "warnings" in body
