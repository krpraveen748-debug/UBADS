"""
Tests for the Phase 11 per-agent-credential authentication foundation and
endpoint-identity routes: POST /api/endpoints/register (enrollment AND
authenticated re-registration), POST /api/endpoints/heartbeat. See
test_ingest_api.py for POST /api/ingest/events. Uses only the isolated
in-memory `endpoints` database (see conftest.py) — never the real
data/app.db.
"""

from app.security import agent_auth


def _enroll(client, monkeypatch, endpoint_id=None, display_name="TEST-PC", enrollment_key="test-secret"):
    monkeypatch.setattr(agent_auth.settings, "agent_api_key", enrollment_key)
    body = {"display_name": display_name}
    if endpoint_id is not None:
        body["endpoint_id"] = endpoint_id
    return client.post(
        "/api/endpoints/register", json=body, headers={"X-Agent-Api-Key": enrollment_key}
    )


def test_enrollment_rejected_when_no_enrollment_key_configured(client, monkeypatch):
    monkeypatch.setattr(agent_auth.settings, "agent_api_key", None)
    response = client.post("/api/endpoints/register", json={"display_name": "TEST-PC"})
    assert response.status_code == 503


def test_enrollment_rejected_with_missing_header(client, monkeypatch):
    monkeypatch.setattr(agent_auth.settings, "agent_api_key", "test-secret")
    response = client.post("/api/endpoints/register", json={"display_name": "TEST-PC"})
    assert response.status_code == 401


def test_enrollment_rejected_with_wrong_key(client, monkeypatch):
    monkeypatch.setattr(agent_auth.settings, "agent_api_key", "test-secret")
    response = client.post(
        "/api/endpoints/register",
        json={"display_name": "TEST-PC"},
        headers={"X-Agent-Api-Key": "wrong-key"},
    )
    assert response.status_code == 401


def test_enrollment_succeeds_and_issues_a_credential(client, monkeypatch):
    response = _enroll(client, monkeypatch)
    assert response.status_code == 200
    body = response.json()
    assert body["endpoint_id"]  # server-assigned since none was provided
    assert body["display_name"] == "TEST-PC"
    assert body["status"] == "registered"
    assert body["agent_credential"]  # issued exactly once, here
    assert body["credential_enrolled"] is True


def test_each_enrolled_endpoint_gets_a_different_credential(client, monkeypatch):
    first = _enroll(client, monkeypatch, endpoint_id="ep-a").json()
    second = _enroll(client, monkeypatch, endpoint_id="ep-b").json()
    assert first["agent_credential"] != second["agent_credential"]


def test_enrollment_key_cannot_re_enroll_an_already_enrolled_endpoint(client, monkeypatch):
    _enroll(client, monkeypatch, endpoint_id="fixed-id-1")
    second = _enroll(client, monkeypatch, endpoint_id="fixed-id-1", display_name="ATTACKER-RENAME")
    assert second.status_code == 409


def test_legacy_endpoint_without_credential_can_be_enrolled_once(client, monkeypatch, endpoint_db_session):
    """Transitional: a Phase 9/10 endpoint row that predates per-agent
    credentials (credential_hash NULL) can still get its first credential
    via the enrollment key — documented as a one-time migration path."""
    from datetime import datetime, timezone

    from app.models.endpoint import EndpointRecord

    legacy = EndpointRecord(
        endpoint_id="legacy-1",
        display_name="LEGACY-PC",
        status="registered",
        registered_at=datetime.now(timezone.utc),
        credential_hash=None,
    )
    endpoint_db_session.add(legacy)
    endpoint_db_session.commit()

    response = _enroll(client, monkeypatch, endpoint_id="legacy-1")
    assert response.status_code == 200
    assert response.json()["agent_credential"]


def test_register_with_valid_credential_refreshes_metadata_without_new_credential(client, monkeypatch):
    enrolled = _enroll(client, monkeypatch, endpoint_id="ep-1").json()
    response = client.post(
        "/api/endpoints/register",
        json={"endpoint_id": "ep-1", "display_name": "RENAMED-PC"},
        headers={"X-Endpoint-Id": "ep-1", "X-Agent-Credential": enrolled["agent_credential"]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["display_name"] == "RENAMED-PC"
    assert body["agent_credential"] is None  # never re-issued on a metadata refresh


def test_register_with_wrong_credential_is_rejected(client, monkeypatch):
    _enroll(client, monkeypatch, endpoint_id="ep-1")
    response = client.post(
        "/api/endpoints/register",
        json={"endpoint_id": "ep-1", "display_name": "RENAMED-PC"},
        headers={"X-Endpoint-Id": "ep-1", "X-Agent-Credential": "not-the-right-credential"},
    )
    assert response.status_code == 401


def test_endpoint_cannot_impersonate_another_endpoint_by_changing_body_id(client, monkeypatch):
    """Endpoint A must not be able to act as endpoint B just by putting B's
    endpoint_id in the request body while authenticating as A."""
    a = _enroll(client, monkeypatch, endpoint_id="ep-a").json()
    _enroll(client, monkeypatch, endpoint_id="ep-b")

    response = client.post(
        "/api/endpoints/register",
        json={"endpoint_id": "ep-b", "display_name": "TAKEOVER-ATTEMPT"},
        headers={"X-Endpoint-Id": "ep-a", "X-Agent-Credential": a["agent_credential"]},
    )
    assert response.status_code == 403


def test_heartbeat_requires_per_agent_credential(client, monkeypatch):
    enrolled = _enroll(client, monkeypatch, endpoint_id="hb-1").json()
    response = client.post(
        "/api/endpoints/heartbeat",
        json={},
        headers={"X-Endpoint-Id": "hb-1", "X-Agent-Credential": enrolled["agent_credential"]},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "active"
    assert response.json()["last_seen"] is not None


def test_heartbeat_rejects_enrollment_key(client, monkeypatch):
    _enroll(client, monkeypatch, endpoint_id="hb-2")
    response = client.post(
        "/api/endpoints/heartbeat",
        json={},
        headers={"X-Agent-Api-Key": "test-secret"},
    )
    assert response.status_code == 401


def test_heartbeat_for_unknown_endpoint_returns_401_not_404(client, monkeypatch):
    """A caller must not be able to distinguish "unknown endpoint" from
    "wrong credential" — both are 401, so endpoint IDs can't be enumerated."""
    monkeypatch.setattr(agent_auth.settings, "agent_api_key", "test-secret")
    response = client.post(
        "/api/endpoints/heartbeat",
        json={},
        headers={"X-Endpoint-Id": "never-registered", "X-Agent-Credential": "whatever"},
    )
    assert response.status_code == 401


def test_heartbeat_rejects_impersonation_via_body_endpoint_id(client, monkeypatch):
    a = _enroll(client, monkeypatch, endpoint_id="ep-a").json()
    _enroll(client, monkeypatch, endpoint_id="ep-b")
    response = client.post(
        "/api/endpoints/heartbeat",
        json={"endpoint_id": "ep-b"},
        headers={"X-Endpoint-Id": "ep-a", "X-Agent-Credential": a["agent_credential"]},
    )
    assert response.status_code == 403


def test_list_endpoints_is_empty_before_any_enrollment(client):
    response = client.get("/api/endpoints")
    assert response.status_code == 200
    assert response.json() == []


def test_list_endpoints_returns_multiple_enrolled_endpoints_without_a_credential(client, monkeypatch):
    """Phase 14: the frontend uses this to populate a per-endpoint filter
    on the Events page — it must never expose a credential or its hash."""
    _enroll(client, monkeypatch, endpoint_id="ep-a", display_name="LAPTOP-A")
    _enroll(client, monkeypatch, endpoint_id="ep-b", display_name="LAPTOP-B")

    response = client.get("/api/endpoints")
    assert response.status_code == 200
    body = response.json()
    ids = {e["endpoint_id"] for e in body}
    assert ids == {"ep-a", "ep-b"}
    for endpoint in body:
        assert "credential_hash" not in endpoint
        assert "agent_credential" not in endpoint
    names = {e["endpoint_id"]: e["display_name"] for e in body}
    assert names == {"ep-a": "LAPTOP-A", "ep-b": "LAPTOP-B"}
