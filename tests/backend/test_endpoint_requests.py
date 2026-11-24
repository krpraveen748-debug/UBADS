"""Phase 17 stage 1: registration, roles, user endpoint requests, isolation,
and the additive migration of pre-Phase-17 dashboard users."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.dashboard_auth import ROLE_ADMIN, ROLE_USER, DashboardUser
from app.models.enrollment import AuditEvent, EndpointRequest, Notification

PASSWORD = "a-long-test-password"


def _register(c, username="alice", **over):
    body = {
        "username": username,
        "password": PASSWORD,
        "email": f"{username}@example.org",
        "full_name": "Test Person",
        "organization": "Example University",
    }
    body.update(over)
    return c.post("/api/auth/register", json=body)


def _login_client(username):
    c = TestClient(app)
    token = c.post("/api/auth/login", json={"username": username, "password": PASSWORD}).json()["access_token"]
    c.headers["Authorization"] = f"Bearer {token}"
    return c


@pytest.fixture()
def alice(anon_client):
    assert _register(anon_client, "alice").status_code == 201
    return _login_client("alice")


@pytest.fixture()
def bob(anon_client):
    assert _register(anon_client, "bob").status_code == 201
    return _login_client("bob")


def _request_body(**over):
    body = {
        "requested_scope": ["authentication", "process_activity"],
        "consent_acknowledged": True,
        "department": "Security Lab",
        "client_hint": {"platform": "Win32", "is_windows": True},
    }
    body.update(over)
    return body


# --- registration / roles ---------------------------------------------------


def test_register_creates_normal_user_never_admin(anon_client, endpoint_db_session):
    assert _register(anon_client).json()["role"] == ROLE_USER
    assert endpoint_db_session.get(DashboardUser, "alice").role == ROLE_USER
    # an attacker-supplied role field is ignored
    assert _register(anon_client, "mallory", role="admin").status_code == 201
    assert endpoint_db_session.get(DashboardUser, "mallory").role == ROLE_USER


def test_register_validation_and_duplicates(anon_client):
    assert _register(anon_client, "x").status_code == 422  # username too short
    assert _register(anon_client, "carol", password="short").status_code == 422
    assert _register(anon_client, "carol", email="not-an-email").status_code == 422
    assert _register(anon_client, "carol").status_code == 201
    assert _register(anon_client, "carol").status_code == 409


def test_registration_can_be_disabled_and_is_rate_limited(anon_client, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "registration_enabled", False)
    assert _register(anon_client).status_code == 403
    monkeypatch.setattr(settings, "registration_enabled", True)
    monkeypatch.setattr(settings, "registration_max_per_hour", 2)
    assert _register(anon_client, "user1").status_code == 201
    assert _register(anon_client, "user2").status_code == 201
    assert _register(anon_client, "user3").status_code == 429


def test_me_returns_role_and_profile(alice, client):
    me = alice.get("/api/auth/me").json()
    assert me["role"] == "user" and me["organization"] == "Example University"
    assert client.get("/api/auth/me").json()["role"] == ROLE_ADMIN


@pytest.mark.parametrize(
    "path",
    ["/api/events", "/api/endpoints", "/api/endpoints/status", "/api/users", "/api/users/baselines",
     "/api/anomalies", "/api/ml/collection-status", "/api/reports/data-quality"],
)
def test_normal_user_cannot_read_any_telemetry_api(alice, path):
    assert alice.get(path).status_code == 403


def test_admin_still_reads_telemetry(client):
    assert client.get("/api/events").status_code == 200
    assert client.get("/api/endpoints").status_code == 200


# --- creating requests ------------------------------------------------------


def test_user_creates_request_pending_with_audit_and_notifications(alice, client, endpoint_db_session):
    r = alice.post("/api/endpoint-requests", json=_request_body())
    assert r.status_code == 201
    out = r.json()
    assert out["status"] == "PENDING" and out["username"] == "alice"
    assert out["organization"] == "Example University"  # defaulted from the account
    assert out["requested_scope"] == ["authentication", "process_activity"]
    assert out["endpoint_id"] is None and out["endpoint_connection_status"] is None
    assert out["client_hint"] == {"platform": "Win32", "is_windows": True}

    audit = endpoint_db_session.query(AuditEvent).filter_by(action="request.created").one()
    assert audit.actor == "alice" and audit.request_id == out["id"]
    kinds = {(n.username, n.kind) for n in endpoint_db_session.query(Notification)}
    assert ("alice", "request.submitted") in kinds
    assert any(u == "test-operator" and k == "request.pending" for u, k in kinds)  # admin alerted


def test_request_requires_consent_and_valid_scope(alice):
    assert alice.post("/api/endpoint-requests", json=_request_body(consent_acknowledged=False)).status_code == 422
    assert alice.post("/api/endpoint-requests", json=_request_body(requested_scope=[])).status_code == 422
    r = alice.post("/api/endpoint-requests", json=_request_body(requested_scope=["keystrokes"]))
    assert r.status_code == 422 and "keystrokes" in r.json()["detail"]
    assert alice.post("/api/endpoint-requests", json=_request_body(requested_scope=["screenshots"])).status_code == 422


def test_request_requires_login(anon_client):
    assert anon_client.post("/api/endpoint-requests", json=_request_body()).status_code == 401
    assert anon_client.get("/api/endpoint-requests/my").status_code == 401


def test_open_request_cap(alice, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "max_open_requests_per_user", 2)
    assert alice.post("/api/endpoint-requests", json=_request_body()).status_code == 201
    assert alice.post("/api/endpoint-requests", json=_request_body()).status_code == 201
    assert alice.post("/api/endpoint-requests", json=_request_body()).status_code == 429


def test_user_cannot_self_approve_or_set_status(alice):
    r = alice.post("/api/endpoint-requests", json=_request_body(status="APPROVED", decided_by="alice"))
    assert r.status_code == 201 and r.json()["status"] == "PENDING" and r.json()["decided_by"] is None


# --- isolation --------------------------------------------------------------


def test_users_only_see_their_own_requests(alice, bob):
    a = alice.post("/api/endpoint-requests", json=_request_body()).json()
    b = bob.post("/api/endpoint-requests", json=_request_body(requested_scope=["authentication"])).json()
    assert [r["id"] for r in alice.get("/api/endpoint-requests/my").json()] == [a["id"]]
    assert [r["id"] for r in bob.get("/api/endpoint-requests/my").json()] == [b["id"]]
    assert alice.get(f"/api/endpoint-requests/{a['id']}").status_code == 200
    # another user's request is indistinguishable from a missing one
    assert alice.get(f"/api/endpoint-requests/{b['id']}").status_code == 404
    assert alice.get("/api/endpoint-requests/does-not-exist").status_code == 404


def test_request_table_has_no_token_or_credential_columns():
    cols = {c.name for c in EndpointRequest.__table__.columns}
    assert not any("token" in c or "credential" in c or "password" in c for c in cols)
