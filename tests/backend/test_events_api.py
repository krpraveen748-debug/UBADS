"""
Tests for GET /api/events and GET /api/events/{id}. Uses only the isolated
in-memory test database (see conftest.py) — never the real data/app.db.
"""

from tests.backend.conftest import insert_fixture_event


def test_list_events_empty_database_returns_empty_list(client):
    response = client.get("/api/events")
    assert response.status_code == 200
    assert response.json() == []


def test_list_events_returns_real_stored_fixture(client, test_session):
    insert_fixture_event(test_session)
    response = client.get("/api/events")
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["username"] == "test.fixture.user"
    assert body[0]["event_category"] == "authentication"
    assert body[0]["event_id"] == 4624
    # Privacy: raw_event_data / user_sid must never appear in the response.
    assert "raw_event_data" not in body[0]
    assert "user_sid" not in body[0]


def test_list_events_filters_by_category(client, test_session):
    insert_fixture_event(test_session, event_record_id="1")
    insert_fixture_event(
        test_session,
        event_record_id="2",
        event_id=4688,
        event_type="process_created",
        event_category="process_activity",
    )

    response = client.get("/api/events", params={"category": "process_activity"})
    body = response.json()
    assert len(body) == 1
    assert body[0]["event_category"] == "process_activity"


def test_list_events_filters_by_username_and_event_id(client, test_session):
    insert_fixture_event(test_session, event_record_id="1", username="alice")
    insert_fixture_event(test_session, event_record_id="2", username="bob")

    response = client.get("/api/events", params={"username": "alice", "event_id": 4624})
    body = response.json()
    assert len(body) == 1
    assert body[0]["username"] == "alice"


def test_list_events_respects_limit(client, test_session):
    for i in range(5):
        insert_fixture_event(test_session, event_record_id=str(i))

    response = client.get("/api/events", params={"limit": 2})
    assert len(response.json()) == 2


def test_get_event_detail_returns_full_normalized_fields(client, test_session):
    insert_fixture_event(test_session)
    listing = client.get("/api/events").json()
    event_pk = listing[0]["id"]

    response = client.get(f"/api/events/{event_pk}")
    assert response.status_code == 200
    body = response.json()
    assert body["logon_type_description"] == "interactive"
    assert "raw_event_data" not in body


def test_get_event_detail_returns_404_when_missing(client):
    response = client.get("/api/events/999999")
    assert response.status_code == 404


def test_event_summary_includes_endpoint_id(client, test_session):
    insert_fixture_event(test_session, endpoint_id="ep-a")
    response = client.get("/api/events")
    assert response.json()[0]["endpoint_id"] == "ep-a"


def test_event_summary_endpoint_id_is_null_for_legacy_rows(client, test_session):
    insert_fixture_event(test_session)  # no endpoint_id — pre-Phase-11-style row
    response = client.get("/api/events")
    assert response.json()[0]["endpoint_id"] is None


def test_list_events_filters_by_endpoint_id_without_mixing(client, test_session):
    """The core Phase 14 requirement: two enrolled endpoints' events must
    be tellable apart, never blended together."""
    insert_fixture_event(test_session, event_record_id="a-1", endpoint_id="ep-a")
    insert_fixture_event(test_session, event_record_id="a-2", endpoint_id="ep-a")
    insert_fixture_event(test_session, event_record_id="b-1", endpoint_id="ep-b")

    response_a = client.get("/api/events", params={"endpoint_id": "ep-a"})
    response_b = client.get("/api/events", params={"endpoint_id": "ep-b"})
    response_all = client.get("/api/events")

    assert len(response_a.json()) == 2
    assert all(e["endpoint_id"] == "ep-a" for e in response_a.json())
    assert len(response_b.json()) == 1
    assert response_b.json()[0]["endpoint_id"] == "ep-b"
    assert len(response_all.json()) == 3


def test_list_events_endpoint_filter_excludes_legacy_null_rows(client, test_session):
    """A row with no endpoint_id (legacy/local-collector) must never be
    silently included when a specific endpoint is requested."""
    insert_fixture_event(test_session, event_record_id="legacy-1")  # endpoint_id=None
    insert_fixture_event(test_session, event_record_id="a-1", endpoint_id="ep-a")

    response = client.get("/api/events", params={"endpoint_id": "ep-a"})
    assert len(response.json()) == 1
    assert response.json()[0]["endpoint_id"] == "ep-a"
