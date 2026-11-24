"""
Tests for GET /api/endpoints/status. Must never claim "online"/"running"
since there is no real heartbeat mechanism — only report facts derivable
from real stored events.
"""

from tests.backend.conftest import insert_fixture_event


def test_endpoint_status_empty_database_is_all_unknown(client):
    response = client.get("/api/endpoints/status")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "unknown"
    assert body["online"] is None
    assert body["collectorRunning"] is None
    assert body["lastEvent"] is None


def test_endpoint_status_never_claims_online_even_with_data(client, test_session):
    insert_fixture_event(test_session, computer_name="TEST-FIXTURE-PC")
    response = client.get("/api/endpoints/status")
    body = response.json()
    # Real, derivable facts:
    assert body["endpointName"] == "TEST-FIXTURE-PC"
    assert body["lastEvent"] is not None
    assert body["currentUser"] == "test.fixture.user"
    # Never fabricated as "online"/"running" — no heartbeat mechanism exists.
    assert body["online"] is None
    assert body["collectorRunning"] is None
    assert body["status"] == "unknown"
