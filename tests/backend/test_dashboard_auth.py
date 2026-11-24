"""Dashboard login/session auth, protection of read APIs, separation from
agent auth, and endpoint connection status."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import settings
from app.models.dashboard_auth import DashboardSession
from app.models.endpoint import EndpointRecord
from app.security import agent_auth, dashboard_auth
from tests.backend.conftest import TEST_DASHBOARD_PASSWORD, TEST_DASHBOARD_USER, insert_fixture_event

PROTECTED_GETS = [
    "/api/events",
    "/api/events/1",
    "/api/endpoints",
    "/api/endpoints/status",
    "/api/users",
    "/api/users/baselines",
    "/api/anomalies",
    "/api/ml/collection-status",
    "/api/reports/data-quality",
    "/api/auth/me",
]


def _login(c, password=TEST_DASHBOARD_PASSWORD, username=TEST_DASHBOARD_USER):
    return c.post("/api/auth/login", json={"username": username, "password": password})


@pytest.fixture()
def user(endpoint_db_session):
    dashboard_auth.create_user(endpoint_db_session, TEST_DASHBOARD_USER, TEST_DASHBOARD_PASSWORD)


@pytest.mark.parametrize("path", PROTECTED_GETS)
def test_unauthenticated_requests_are_rejected(anon_client, path):
    assert anon_client.get(path).status_code == 401


def test_garbage_and_non_bearer_tokens_rejected(anon_client):
    assert anon_client.get("/api/events", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert anon_client.get("/api/events", headers={"Authorization": "Basic abc"}).status_code == 401


def test_health_and_ready_stay_open(anon_client):
    assert anon_client.get("/health").status_code == 200


def test_login_success_grants_access(anon_client, user):
    response = _login(anon_client)
    assert response.status_code == 200
    token = response.json()["access_token"]
    assert anon_client.get("/api/events", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_invalid_login_is_identical_for_wrong_password_and_unknown_user(anon_client, user):
    wrong = _login(anon_client, password="wrong-password-xx")
    unknown = _login(anon_client, username="nobody")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()
    assert "access_token" not in wrong.json()


def test_repeated_failures_lock_out_even_the_right_password(anon_client, user):
    for _ in range(settings.dashboard_login_max_failures):
        assert _login(anon_client, password="wrong-password-xx").status_code == 401
    assert _login(anon_client).status_code == 429


def test_expired_session_rejected(anon_client, endpoint_db_session, user):
    token = _login(anon_client).json()["access_token"]
    record = endpoint_db_session.query(DashboardSession).one()
    record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    endpoint_db_session.commit()
    response = anon_client.get("/api/events", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()


def test_logout_revokes_token(anon_client, user):
    token = _login(anon_client).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert anon_client.post("/api/auth/logout", headers=headers).status_code == 200
    assert anon_client.get("/api/events", headers=headers).status_code == 401


def test_passwords_and_tokens_are_not_stored_in_plaintext(anon_client, endpoint_db_session, user):
    token = _login(anon_client).json()["access_token"]
    stored = endpoint_db_session.query(dashboard_auth.DashboardUser).one().password_hash
    assert TEST_DASHBOARD_PASSWORD not in stored and stored.startswith("scrypt$")
    assert endpoint_db_session.query(DashboardSession).one().token_hash != token


def test_short_password_rejected(endpoint_db_session):
    with pytest.raises(ValueError):
        dashboard_auth.create_user(endpoint_db_session, "x", "short")


def _enroll(c, monkeypatch, name="PC-A"):
    monkeypatch.setattr(agent_auth.settings, "agent_api_key", "enroll-key")
    r = c.post("/api/endpoints/register", json={"display_name": name}, headers={"X-Agent-Api-Key": "enroll-key"})
    assert r.status_code == 200
    return r.json()


def test_agent_credentials_cannot_read_dashboard_apis(anon_client, monkeypatch):
    ep = _enroll(anon_client, monkeypatch)
    headers = {"X-Endpoint-Id": ep["endpoint_id"], "X-Agent-Credential": ep["agent_credential"]}
    assert anon_client.get("/api/endpoints", headers=headers).status_code == 401
    assert anon_client.get("/api/events", headers=headers).status_code == 401


def test_dashboard_token_cannot_act_as_agent(client, anon_client):
    # `client` carries a valid dashboard session; agent routes must ignore it.
    assert client.post("/api/endpoints/heartbeat").status_code == 401
    assert client.post("/api/ingest/events", json={"log_name": "Security", "events": []}).status_code == 401


def test_agent_flow_works_without_dashboard_login(anon_client, monkeypatch):
    ep = _enroll(anon_client, monkeypatch)
    headers = {"X-Endpoint-Id": ep["endpoint_id"], "X-Agent-Credential": ep["agent_credential"]}
    assert anon_client.post("/api/endpoints/heartbeat", headers=headers).status_code == 200
    r = anon_client.post("/api/ingest/events", json={"log_name": "Security", "events": []}, headers=headers)
    assert r.status_code == 200


def test_connection_status_online_stale_offline(client, endpoint_db_session, monkeypatch):
    ep = _enroll(client, monkeypatch)
    assert client.get("/api/endpoints").json()[0]["connection_status"] == "online"
    record = endpoint_db_session.get(EndpointRecord, ep["endpoint_id"])
    for age, expected in [(200, "stale"), (3600, "offline")]:
        record.last_seen = datetime.now(timezone.utc) - timedelta(seconds=age)
        endpoint_db_session.commit()
        assert client.get("/api/endpoints").json()[0]["connection_status"] == expected


def test_heartbeat_brings_endpoint_back_online(client, endpoint_db_session, monkeypatch):
    ep = _enroll(client, monkeypatch)
    endpoint_db_session.get(EndpointRecord, ep["endpoint_id"]).last_seen = datetime.now(timezone.utc) - timedelta(hours=1)
    endpoint_db_session.commit()
    assert client.get("/api/endpoints").json()[0]["connection_status"] == "offline"
    h = {"X-Endpoint-Id": ep["endpoint_id"], "X-Agent-Credential": ep["agent_credential"]}
    client.post("/api/endpoints/heartbeat", headers=h)
    assert client.get("/api/endpoints").json()[0]["connection_status"] == "online"


def test_events_filter_by_endpoint_never_mixes(client, test_session):
    insert_fixture_event(test_session, "1", endpoint_id="ep-a")
    insert_fixture_event(test_session, "2", endpoint_id="ep-b")
    insert_fixture_event(test_session, "3", endpoint_id="ep-b")
    insert_fixture_event(test_session, "4", endpoint_id=None)
    a = client.get("/api/events", params={"endpoint_id": "ep-a"}).json()
    b = client.get("/api/events", params={"endpoint_id": "ep-b"}).json()
    assert len(a) == 1 and {e["endpoint_id"] for e in a} == {"ep-a"}
    assert len(b) == 2 and {e["endpoint_id"] for e in b} == {"ep-b"}
