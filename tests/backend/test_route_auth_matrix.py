"""Regression guard for the authentication model (Phase 17 review).

1. The auth requirement of EVERY route is pinned in a table, so a new or
   changed route cannot silently become unprotected or change mechanism.
2. Agent routes authenticate ONLY with the per-endpoint credential and are
   independent of dashboard users/roles.
3. The real agent BackendClient still works end to end against the app
   without any dashboard session.
"""

import pytest
import requests
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.main import app
from app.security import agent_auth
from tests.backend.conftest import insert_fixture_event  # noqa: F401  (fixture module import)

# mechanism: admin | user (any signed-in dashboard account) | agent | open | enrollment
EXPECTED = {
    ("GET", "/api/anomalies"): "admin",
    ("GET", "/api/anomalies/{anomaly_id}"): "admin",
    ("GET", "/api/endpoints"): "admin",
    ("GET", "/api/endpoints/status"): "admin",
    ("GET", "/api/events"): "admin",
    ("GET", "/api/events/{event_pk}"): "admin",
    ("GET", "/api/ml/collection-status"): "admin",
    ("GET", "/api/ml/anomaly-status"): "admin",
    ("GET", "/api/ml/synthetic-experiment"): "admin",
    ("GET", "/api/ml/synthetic-experiment/samples"): "admin",
    ("POST", "/api/ml/train-anomaly-models"): "admin",
    ("GET", "/api/reports/data-quality"): "admin",
    ("GET", "/api/users"): "admin",
    ("GET", "/api/users/baselines"): "admin",
    ("GET", "/api/admin/endpoint-requests"): "admin",
    ("GET", "/api/admin/endpoint-requests/{request_id}"): "admin",
    ("POST", "/api/admin/endpoint-requests/{request_id}/approve"): "admin",
    ("POST", "/api/admin/endpoint-requests/{request_id}/reject"): "admin",
    ("POST", "/api/admin/endpoint-requests/{request_id}/revoke"): "admin",
    ("GET", "/api/admin/audit"): "admin",
    ("POST", "/api/admin/auth/unlock"): "admin",
    ("GET", "/api/notifications"): "user",
    ("GET", "/api/notifications/unread-count"): "user",
    ("POST", "/api/notifications/read-all"): "user",
    ("POST", "/api/notifications/{notification_id}/read"): "user",
    ("GET", "/api/endpoint-requests/{request_id}/download-info"): "user",
    ("POST", "/api/endpoint-requests/{request_id}/enrollment-package"): "user",
    ("POST", "/api/agent/enrollment/redeem"): "code",
    ("POST", "/api/endpoint-requests"): "user",
    ("GET", "/api/endpoint-requests/my"): "user",
    ("GET", "/api/endpoint-requests/{request_id}"): "user",
    ("GET", "/api/auth/me"): "user",
    ("POST", "/api/auth/logout"): "user",
    ("POST", "/api/endpoints/heartbeat"): "agent",
    ("POST", "/api/ingest/events"): "agent",
    ("POST", "/api/endpoints/register"): "enrollment",  # enrollment key OR agent credential, checked in-handler
    ("POST", "/api/auth/login"): "open",
    ("POST", "/api/auth/register"): "open",
    ("GET", "/health"): "open",
    ("GET", "/ready"): "open",
}


def _dep_names(dependant, acc=None):
    acc = set() if acc is None else acc
    for d in dependant.dependencies:
        acc.add(getattr(d.call, "__name__", str(d.call)))
        _dep_names(d, acc)
    return acc


def _classify(route):
    names = _dep_names(route.dependant)
    if "require_authenticated_endpoint" in names:
        assert not names & {"require_admin", "get_current_user", "require_dashboard_user"}, "agent route must not depend on dashboard auth"
        return "agent"
    if "require_admin" in names:
        return "admin"
    if names & {"get_current_user", "require_dashboard_user"}:
        return "user"
    if route.path == "/api/agent/enrollment/redeem":
        return "code"  # authenticated by the one-time enrollment code in the body
    return "enrollment" if route.path == "/api/endpoints/register" else "open"


def test_every_route_has_the_pinned_authentication_requirement():
    actual = {}
    for route in app.routes:
        if isinstance(route, APIRoute):
            for method in route.methods - {"HEAD", "OPTIONS"}:
                actual[(method, route.path)] = _classify(route)
    assert actual == EXPECTED, "route/auth table changed - review the security impact, then update EXPECTED"


def _enroll(c, monkeypatch, name="PC"):
    monkeypatch.setattr(agent_auth.settings, "agent_api_key", "enroll-key")
    r = c.post("/api/endpoints/register", json={"display_name": name}, headers={"X-Agent-Api-Key": "enroll-key"})
    assert r.status_code == 200
    d = r.json()
    return {"X-Endpoint-Id": d["endpoint_id"], "X-Agent-Credential": d["agent_credential"]}


def _register_normal_user(c, name="eve"):
    c.post("/api/auth/register", json={"username": name, "password": "a-long-test-password", "email": f"{name}@x.org", "full_name": "E", "organization": "Org"})
    t = c.post("/api/auth/login", json={"username": name, "password": "a-long-test-password"}).json()["access_token"]
    return {"Authorization": f"Bearer {t}"}


def test_agent_routes_work_with_no_dashboard_users_at_all(anon_client, monkeypatch):
    """No dashboard account exists in this database; agents must be unaffected."""
    h = _enroll(anon_client, monkeypatch)
    assert anon_client.post("/api/endpoints/heartbeat", headers=h).status_code == 200
    assert anon_client.post("/api/ingest/events", json={"log_name": "Security", "events": []}, headers=h).status_code == 200
    assert anon_client.post("/api/endpoints/register", json={"display_name": "PC2"}, headers=h).status_code == 200


def test_agent_routes_ignore_dashboard_roles_and_sessions(client, anon_client, monkeypatch):
    h = _enroll(client, monkeypatch)
    user_h = _register_normal_user(anon_client)
    # A valid agent credential works regardless of who is (or is not) signed in,
    # even when the request also carries a normal user's or admin's bearer token.
    for extra in ({}, user_h, {"Authorization": client.headers["Authorization"]}):
        assert anon_client.post("/api/endpoints/heartbeat", headers={**h, **extra}).status_code == 200


def test_dashboard_sessions_of_any_role_cannot_act_as_an_agent(client, anon_client):
    user_h = _register_normal_user(anon_client)
    admin_h = {"Authorization": client.headers["Authorization"]}
    for h in (user_h, admin_h):
        assert anon_client.post("/api/endpoints/heartbeat", headers=h).status_code == 401
        assert anon_client.post("/api/ingest/events", json={"log_name": "Security", "events": []}, headers=h).status_code == 401


def test_agent_credentials_cannot_reach_dashboard_or_admin_apis(anon_client, monkeypatch):
    h = _enroll(anon_client, monkeypatch)
    for path in ("/api/events", "/api/endpoints", "/api/auth/me", "/api/endpoint-requests/my"):
        assert anon_client.get(path, headers=h).status_code == 401


def test_enrollment_key_still_required_and_not_replaced_by_dashboard_auth(client, anon_client, monkeypatch):
    monkeypatch.setattr(agent_auth.settings, "agent_api_key", "enroll-key")
    admin_h = {"Authorization": client.headers["Authorization"]}
    # Even a logged-in ADMIN cannot enroll an endpoint without the enrollment key.
    assert anon_client.post("/api/endpoints/register", json={"display_name": "X"}, headers=admin_h).status_code == 401
    assert anon_client.post("/api/endpoints/register", json={"display_name": "X"}, headers={"X-Agent-Api-Key": "wrong"}).status_code == 401


def test_normal_user_gets_403_on_every_admin_route(anon_client):
    user_h = _register_normal_user(anon_client)
    for (method, path), mech in EXPECTED.items():
        if mech == "admin":
            url = path.replace("{event_pk}", "1").replace("{request_id}", "x")
            assert anon_client.request(method, url, headers=user_h).status_code == 403, path


def test_real_agent_backend_client_still_works_without_a_dashboard_session(anon_client, monkeypatch):
    """Drives the REAL agent/backend_client.py against the app (requests is
    redirected into the in-process app). No dashboard login is involved."""
    import backend_client
    from backend_client import BackendClient

    def fake_request(method, url, json=None, headers=None, timeout=None):
        path = url.split("://", 1)[1].split("/", 1)[1]
        r = anon_client.request(method, "/" + path, json=json, headers=headers)

        class _Resp:
            status_code = r.status_code
            text = r.text

            def json(self_inner):
                return r.json()

        return _Resp()

    monkeypatch.setattr(requests, "request", fake_request)
    monkeypatch.setattr(backend_client.settings, "agent_api_key", "enroll-key")
    monkeypatch.setattr(agent_auth.settings, "agent_api_key", "enroll-key")

    client = BackendClient("http://127.0.0.1:8000")
    assert client.check_health().ok
    enrolled = client.enroll_endpoint(endpoint_id=None, display_name="PC", operating_system="Windows", agent_version="t")
    assert enrolled.ok and enrolled.data["agent_credential"]
    eid, cred = enrolled.data["endpoint_id"], enrolled.data["agent_credential"]
    assert client.register(endpoint_id=eid, agent_credential=cred, display_name="PC", operating_system="W", agent_version="t").ok
    assert client.heartbeat(endpoint_id=eid, agent_credential=cred).ok
    event = {"event_id": 4624, "event_type": "successful_logon", "timestamp": "2026-01-01T00:00:00.000000Z",
             "computer_name": "REGRESSION-FIXTURE", "username": "fixture", "event_record_id": 1}
    result = client.ingest_events(endpoint_id=eid, agent_credential=cred, log_name="Security", events=[event])
    assert result.ok and result.data["accepted"] == 1 and result.data["endpoint_id"] == eid
    assert not client.heartbeat(endpoint_id=eid, agent_credential="wrong").ok  # still rejects bad credentials
