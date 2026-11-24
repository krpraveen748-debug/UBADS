"""
Tests for POST /api/ingest/events (Phase 10 minimal ingestion, Phase 11
per-agent authentication + endpoint attribution). Uses only the isolated
in-memory events/endpoints databases (see conftest.py) — never the real
data/app.db. Event dicts below are INGEST-API-TEST FIXTURES ONLY, not real
collected data.
"""

from app.security import agent_auth


def _valid_event(event_record_id="ingest-1", **overrides):
    base = {
        "event_id": 4624,
        "event_record_id": event_record_id,
        "event_type": "successful_logon",
        "event_category": "authentication",
        "timestamp": "2026-03-05T09:00:00.000000Z",
        "computer_name": "TEST-FIXTURE-PC",
        "username": "test.fixture.user",
        "domain": "FIXTURE-DOMAIN",
        "account_type": "human_or_unknown",
        "logon_type": 2,
        "raw_event_data": {},
    }
    base.update(overrides)
    return base


def _enroll(client, monkeypatch, endpoint_id):
    monkeypatch.setattr(agent_auth.settings, "agent_api_key", "test-secret")
    response = client.post(
        "/api/endpoints/register",
        json={"endpoint_id": endpoint_id, "display_name": "TEST-PC"},
        headers={"X-Agent-Api-Key": "test-secret"},
    )
    return response.json()


def test_ingest_requires_auth(client, monkeypatch):
    response = client.post("/api/ingest/events", json={"events": []})
    assert response.status_code == 401


def test_ingest_rejects_enrollment_key_alone(client, monkeypatch):
    monkeypatch.setattr(agent_auth.settings, "agent_api_key", "test-secret")
    response = client.post(
        "/api/ingest/events",
        json={"events": []},
        headers={"X-Agent-Api-Key": "test-secret"},
    )
    assert response.status_code == 401


def test_ingest_accepts_valid_event_from_enrolled_endpoint(client, monkeypatch):
    enrolled = _enroll(client, monkeypatch, "ep-1")
    headers = {"X-Endpoint-Id": "ep-1", "X-Agent-Credential": enrolled["agent_credential"]}

    response = client.post(
        "/api/ingest/events",
        json={"log_name": "Security", "events": [_valid_event()]},
        headers=headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == 1
    assert body["duplicates"] == 0
    assert body["validation_errors"] == 0
    assert body["endpoint_id"] == "ep-1"


def test_model_storage_failure_does_not_undo_accepted_event(client, monkeypatch, test_session):
    from app.api import ingest as ingest_api
    from app.repositories.pipeline_bridge import storage
    from model_storage import ModelStorageUnavailableError

    def fail_model_load(*args, **kwargs):
        raise ModelStorageUnavailableError("Model artifact storage is unavailable.")

    monkeypatch.setattr(ingest_api.anomaly_service, "load_profile_model", fail_model_load)
    enrolled = _enroll(client, monkeypatch, "ep-storage-failure")
    headers = {
        "X-Endpoint-Id": "ep-storage-failure",
        "X-Agent-Credential": enrolled["agent_credential"],
    }

    response = client.post(
        "/api/ingest/events",
        json={"log_name": "Security", "events": [_valid_event(event_record_id="storage-failure")]},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["accepted"] == 1
    rows = storage.get_all_events(test_session, endpoint_id="ep-storage-failure")
    assert len(rows) == 1


def test_ingest_rejects_wrong_credential(client, monkeypatch):
    _enroll(client, monkeypatch, "ep-1")
    response = client.post(
        "/api/ingest/events",
        json={"log_name": "Security", "events": [_valid_event()]},
        headers={"X-Endpoint-Id": "ep-1", "X-Agent-Credential": "not-the-right-one"},
    )
    assert response.status_code == 401


def test_ingest_deduplicates_same_event_uid_for_same_endpoint(client, monkeypatch):
    enrolled = _enroll(client, monkeypatch, "ep-1")
    headers = {"X-Endpoint-Id": "ep-1", "X-Agent-Credential": enrolled["agent_credential"]}
    payload = {"log_name": "Security", "events": [_valid_event(event_record_id="dup-1")]}

    first = client.post("/api/ingest/events", json=payload, headers=headers).json()
    second = client.post("/api/ingest/events", json=payload, headers=headers).json()

    assert first["accepted"] == 1
    assert second["accepted"] == 0
    assert second["duplicates"] == 1


def test_ingest_rejects_invalid_event_without_storing_it(client, monkeypatch):
    enrolled = _enroll(client, monkeypatch, "ep-1")
    headers = {"X-Endpoint-Id": "ep-1", "X-Agent-Credential": enrolled["agent_credential"]}
    invalid = _valid_event(event_record_id="bad-1")
    invalid["event_id"] = None  # required field missing -> must fail validation

    response = client.post(
        "/api/ingest/events",
        json={"log_name": "Security", "events": [invalid]},
        headers=headers,
    )
    body = response.json()
    assert body["accepted"] == 0
    assert body["validation_errors"] == 1
    assert "missing_event_id" in body["errors"][0]["errors"]

    # Confirm it truly never entered storage.
    listing = client.get("/api/events").json()
    assert listing == []


def test_ingest_handles_mixed_batch(client, monkeypatch):
    enrolled = _enroll(client, monkeypatch, "ep-1")
    headers = {"X-Endpoint-Id": "ep-1", "X-Agent-Credential": enrolled["agent_credential"]}
    valid_one = _valid_event(event_record_id="mix-1")
    invalid_one = _valid_event(event_record_id="mix-2")
    invalid_one["computer_name"] = None  # required field missing

    response = client.post(
        "/api/ingest/events",
        json={"log_name": "Security", "events": [valid_one, invalid_one]},
        headers=headers,
    )
    body = response.json()
    assert body["accepted"] == 1
    assert body["validation_errors"] == 1


def test_ingest_rejects_impersonation_via_body_endpoint_id(client, monkeypatch):
    """Endpoint A authenticates with its own credential but claims
    endpoint_id B in the body — must be rejected, not silently corrected."""
    enrolled_a = _enroll(client, monkeypatch, "ep-a")
    _enroll(client, monkeypatch, "ep-b")
    headers = {"X-Endpoint-Id": "ep-a", "X-Agent-Credential": enrolled_a["agent_credential"]}

    response = client.post(
        "/api/ingest/events",
        json={"log_name": "Security", "endpoint_id": "ep-b", "events": [_valid_event()]},
        headers=headers,
    )
    assert response.status_code == 403


def test_ingest_events_are_attributed_to_the_authenticated_endpoint_not_the_body(client, monkeypatch, test_session):
    """Even if a submitted event dict itself carried an 'endpoint_id' key,
    only the AUTHENTICATED endpoint is ever stored — see
    storage.insert_event()'s explicit endpoint_id parameter."""
    from app.repositories.pipeline_bridge import storage

    enrolled = _enroll(client, monkeypatch, "ep-1")
    headers = {"X-Endpoint-Id": "ep-1", "X-Agent-Credential": enrolled["agent_credential"]}
    event = _valid_event(event_record_id="attr-1")
    event["endpoint_id"] = "spoofed-endpoint"  # not a real field the schema even accepts on the event dict

    client.post("/api/ingest/events", json={"log_name": "Security", "events": [event]}, headers=headers)

    rows = storage.get_all_events(test_session)
    assert len(rows) == 1
    assert rows[0].endpoint_id == "ep-1"


def test_two_endpoints_reporting_the_same_computer_and_record_id_are_not_conflated(client, monkeypatch, test_session):
    """Dedup keys are namespaced per authenticated endpoint (Phase 11) —
    two different enrolled endpoints reporting identical
    computer_name/event_record_id (e.g. a misconfigured/spoofed
    computer_name) must both be stored, not treated as duplicates of the
    same event."""
    from app.repositories.pipeline_bridge import storage

    enrolled_a = _enroll(client, monkeypatch, "ep-a")
    enrolled_b = _enroll(client, monkeypatch, "ep-b")

    shared_event = _valid_event(event_record_id="shared-1")
    client.post(
        "/api/ingest/events",
        json={"log_name": "Security", "events": [shared_event]},
        headers={"X-Endpoint-Id": "ep-a", "X-Agent-Credential": enrolled_a["agent_credential"]},
    )
    response_b = client.post(
        "/api/ingest/events",
        json={"log_name": "Security", "events": [shared_event]},
        headers={"X-Endpoint-Id": "ep-b", "X-Agent-Credential": enrolled_b["agent_credential"]},
    )

    assert response_b.json()["accepted"] == 1
    rows = storage.get_all_events(test_session)
    assert len(rows) == 2
    assert {r.endpoint_id for r in rows} == {"ep-a", "ep-b"}
