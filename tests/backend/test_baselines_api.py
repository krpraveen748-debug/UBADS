"""
Tests for GET /api/users/baselines. Uses only the isolated in-memory test
database (see conftest.py) — never the real data/app.db.
"""

from tests.backend.conftest import insert_fixture_event


def test_baselines_empty_database_returns_empty_list(client):
    response = client.get("/api/users/baselines")
    assert response.status_code == 200
    assert response.json() == []


def test_baselines_reports_insufficient_data_honestly_with_thin_history(client, test_session):
    insert_fixture_event(test_session, username="alice")
    response = client.get("/api/users/baselines")
    body = response.json()
    assert len(body) == 1
    assert body[0]["username"] == "alice"
    # No behavior_features rows exist for this fixture (no feature
    # engineering was run) — must be reported honestly, never invented.
    assert body[0]["baselineStatus"] == "insufficient_data"
    assert body[0]["mlReadiness"] == "Insufficient real data"
    assert body[0]["typicalLoginWindow"] == "Insufficient data"


def test_baselines_excludes_service_accounts(client, test_session):
    insert_fixture_event(
        test_session,
        username="SYSTEM",
        domain="NT AUTHORITY",
        user_sid="S-1-5-18",
        account_type="system",
    )
    response = client.get("/api/users/baselines")
    assert response.json() == []
