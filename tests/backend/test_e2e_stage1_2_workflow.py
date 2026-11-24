"""
Automated end-to-end verification of Phase 17 stages 1-2 (scenarios 1-7).

Every scenario drives the real FastAPI app over HTTP (TestClient) with an
isolated in-memory SQLite database from conftest.py - never data/app.db - and
uses test-only accounts created inside that database. No agent, endpoint
credential or event from a real machine is involved.
"""

import logging

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.models.dashboard_auth import DashboardSession, DashboardUser
from app.models.enrollment import AuditEvent, EndpointRequest, Notification
from app.security import dashboard_auth, rate_limit
from tests.backend.conftest import TEST_DASHBOARD_PASSWORD, TEST_DASHBOARD_USER

PW = "e2e-test-password-1"


def _signup(anon, username, **over):
    body = {"username": username, "password": PW, "email": f"{username}@e2e.test", "full_name": f"{username} Person", "organization": "E2E Org"}
    body.update(over)
    return anon.post("/api/auth/register", json=body)


def _client_for(username, password=PW):
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    c.headers["Authorization"] = f"Bearer {r.json()['access_token']}"
    return c


def _body(**over):
    body = {
        "organization": "E2E Org",
        "department": "E2E Dept",
        "requested_scope": ["authentication"],
        "consent_acknowledged": True,
    }
    body.update(over)
    return body


# ============================================================================
# Test 1 - normal user registration
# ============================================================================


def test_1_registration(anon_client, endpoint_db_session):
    r = _signup(anon_client, "e2e-user1")
    assert r.status_code == 201 and r.json()["role"] == "user"
    stored = endpoint_db_session.get(DashboardUser, "e2e-user1")
    assert stored.role == "user" and stored.organization == "E2E Org"
    assert PW not in stored.password_hash and stored.password_hash.startswith("scrypt$")

    # A visitor cannot make themselves an administrator, by any field.
    attempts = {"spoof-role": {"role": "admin"}, "spoof-flag": {"is_admin": True}, "spoof-list": {"roles": ["admin"]}}
    for name, extra in attempts.items():
        assert _signup(anon_client, name, **extra).status_code == 201
        assert endpoint_db_session.get(DashboardUser, name).role == "user"
        assert _client_for(name).get("/api/admin/endpoint-requests").status_code == 403
    assert _client_for("e2e-user1").get("/api/admin/endpoint-requests").status_code == 403

    # Duplicate registration: safe, generic, and it does not touch the original.
    dup = _signup(anon_client, "e2e-user1", password="a-different-password-9")
    assert dup.status_code == 409 and "username" not in dup.json()["detail"].lower()
    assert anon_client.post("/api/auth/login", json={"username": "e2e-user1", "password": "a-different-password-9"}).status_code == 401
    assert anon_client.post("/api/auth/login", json={"username": "e2e-user1", "password": PW}).status_code == 200
    assert endpoint_db_session.query(DashboardUser).filter_by(username="e2e-user1").count() == 1


# ============================================================================
# Test 2 - normal user authentication
# ============================================================================


def test_2_authentication(anon_client, endpoint_db_session, caplog):
    _signup(anon_client, "e2e-user2")
    with caplog.at_level(logging.DEBUG):
        ok = anon_client.post("/api/auth/login", json={"username": "e2e-user2", "password": PW})
        bad = anon_client.post("/api/auth/login", json={"username": "e2e-user2", "password": "wrong-password-1"})
        ghost = anon_client.post("/api/auth/login", json={"username": "no-such-user", "password": "wrong-password-1"})
    assert ok.status_code == 200
    token = ok.json()["access_token"]
    assert ok.json()["role"] == "user" and ok.json()["token_type"] == "bearer" and ok.json()["expires_at"]
    assert set(ok.json()) == {"access_token", "token_type", "expires_at", "username", "role"}  # no hashes / extra data

    me = anon_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    assert me == {"username": "e2e-user2", "role": "user", "email": "e2e-user2@e2e.test", "full_name": "e2e-user2 Person", "organization": "E2E Org"}

    assert bad.status_code == ghost.status_code == 401 and bad.json() == ghost.json()
    assert anon_client.get("/api/auth/me").status_code == 401
    assert anon_client.get("/api/auth/me", headers={"Authorization": "Bearer not-a-token"}).status_code == 401

    # Only a hash of the session token is stored, and no secret reaches the logs.
    assert endpoint_db_session.query(DashboardSession).one().token_hash != token
    logs = caplog.text
    assert token not in logs and PW not in logs and "wrong-password-1" not in logs


# ============================================================================
# Test 3 - endpoint request submission
# ============================================================================


def test_3_request_submission(anon_client, client, endpoint_db_session):
    _signup(anon_client, "e2e-user3")
    user = _client_for("e2e-user3")
    r = user.post("/api/endpoint-requests", json=_body())
    assert r.status_code == 201
    req = r.json()
    assert req["status"] == "PENDING" and req["requested_scope"] == ["authentication"]
    assert req["organization"] == "E2E Org" and req["department"] == "E2E Dept" and req["username"] == "e2e-user3"
    assert req["approved_scope"] is None and req["decided_by"] is None and req["endpoint_id"] is None

    row = endpoint_db_session.get(EndpointRequest, req["id"])
    assert row.consent_acknowledged_at is not None and row.consent_version == settings.consent_version

    audit = endpoint_db_session.query(AuditEvent).filter_by(request_id=req["id"]).all()
    assert [(a.actor, a.action) for a in audit] == [("e2e-user3", "request.created")]
    assert "scope=authentication" in audit[0].detail

    notes = {(n.username, n.kind) for n in endpoint_db_session.query(Notification).filter_by(request_id=req["id"])}
    assert ("e2e-user3", "request.submitted") in notes  # requester told it is pending
    assert (TEST_DASHBOARD_USER, "request.pending") in notes  # administrator told to review
    assert not any(u == "e2e-user3" and k == "request.pending" for u, k in notes)


# ============================================================================
# Test 4 - request ownership
# ============================================================================


def test_4_request_ownership(anon_client, endpoint_db_session):
    _signup(anon_client, "owner-a")
    _signup(anon_client, "other-b")
    a, b = _client_for("owner-a"), _client_for("other-b")
    rid = a.post("/api/endpoint-requests", json=_body()).json()["id"]

    assert a.get(f"/api/endpoint-requests/{rid}").json()["id"] == rid
    assert [r["id"] for r in a.get("/api/endpoint-requests/my").json()] == [rid]

    assert b.get(f"/api/endpoint-requests/{rid}").status_code == 404  # same answer as "does not exist"
    assert b.get("/api/endpoint-requests/my").json() == []
    assert b.get(f"/api/admin/endpoint-requests/{rid}").status_code == 403
    assert b.get("/api/admin/endpoint-requests").status_code == 403

    for path in (f"/api/endpoint-requests/{rid}", "/api/endpoint-requests/my"):
        assert anon_client.get(path).status_code == 401
    assert anon_client.post("/api/endpoint-requests", json=_body()).status_code == 401


# ============================================================================
# Test 5 - admin request management
# ============================================================================


def test_5_admin_management(anon_client, client, endpoint_db_session):
    _signup(anon_client, "e2e-user5")
    user = _client_for("e2e-user5")
    first = user.post("/api/endpoint-requests", json=_body()).json()
    second = user.post("/api/endpoint-requests", json=_body(department="Second Dept")).json()
    third = user.post("/api/endpoint-requests", json=_body(department="Third Dept")).json()

    # list + inspect
    listing = client.get("/api/admin/endpoint-requests").json()
    assert listing["total"] == 3 and listing["counts"]["PENDING"] == 3
    detail = client.get(f"/api/admin/endpoint-requests/{first['id']}").json()
    assert detail["requester_email"] == "e2e-user5@e2e.test" and [h["action"] for h in detail["audit_history"]] == ["request.created"]

    # approve
    approved = client.post(f"/api/admin/endpoint-requests/{first['id']}/approve", json={"note": "approved for the lab"}).json()
    assert approved["status"] == "APPROVED" and approved["decided_by"] == TEST_DASHBOARD_USER
    assert approved["approved_scope"] == ["authentication"] and approved["status_reason"] == "approved for the lab"
    assert [h["action"] for h in approved["audit_history"]] == ["request.approved", "request.created"]
    assert user.get(f"/api/endpoint-requests/{first['id']}").json()["status"] == "APPROVED"

    # reject with a reason
    assert client.post(f"/api/admin/endpoint-requests/{second['id']}/reject", json={}).status_code == 422
    rejected = client.post(f"/api/admin/endpoint-requests/{second['id']}/reject", json={"reason": "Not an authorized machine"}).json()
    assert rejected["status"] == "REJECTED" and rejected["status_reason"] == "Not an authorized machine"
    rej_audit = [h for h in rejected["audit_history"] if h["action"] == "request.rejected"]
    assert len(rej_audit) == 1 and rej_audit[0]["actor"] == TEST_DASHBOARD_USER and "Not an authorized machine" in rej_audit[0]["detail"]

    # revoke the approved one
    revoked = client.post(f"/api/admin/endpoint-requests/{first['id']}/revoke", json={"reason": "no longer needed"}).json()
    assert revoked["status"] == "REVOKED"
    assert [h["action"] for h in revoked["audit_history"]][:2] == ["request.revoked", "request.approved"]

    # the user was notified of each decision
    kinds = [n.kind for n in endpoint_db_session.query(Notification).filter_by(username="e2e-user5").order_by(Notification.id)]
    assert {"request.approved", "request.rejected", "request.revoked"} <= set(kinds)

    # history stays visible and filterable; the third request is untouched
    assert client.get("/api/admin/endpoint-requests", params={"status": "REJECTED"}).json()["total"] == 1
    assert client.get(f"/api/admin/endpoint-requests/{third['id']}").json()["status"] == "PENDING"

    # normal users get 403 on every admin operation, including their own request
    for method, url, body in [
        ("GET", "/api/admin/endpoint-requests", None),
        ("GET", f"/api/admin/endpoint-requests/{third['id']}", None),
        ("POST", f"/api/admin/endpoint-requests/{third['id']}/approve", {}),
        ("POST", f"/api/admin/endpoint-requests/{third['id']}/reject", {"reason": "self reject"}),
        ("POST", f"/api/admin/endpoint-requests/{third['id']}/revoke", {}),
        ("GET", "/api/admin/audit", None),
        ("POST", "/api/admin/auth/unlock", {"username": TEST_DASHBOARD_USER}),
    ]:
        assert user.request(method, url, json=body).status_code == 403, url
    assert client.get(f"/api/admin/endpoint-requests/{third['id']}").json()["status"] == "PENDING"  # nothing slipped through


# ============================================================================
# Test 6 - monitoring scope validation and consent
# ============================================================================


def test_6_scope_and_consent(anon_client, endpoint_db_session, monkeypatch):
    monkeypatch.setattr(settings, "max_open_requests_per_user", 100)
    monkeypatch.setattr(settings, "request_create_max_per_hour", 100)
    _signup(anon_client, "e2e-user6")
    user = _client_for("e2e-user6")

    for valid in ("authentication", "file_activity", "process_activity", "device_activity"):
        assert user.post("/api/endpoint-requests", json=_body(requested_scope=[valid])).status_code == 201, valid
    assert user.post("/api/endpoint-requests", json=_body(requested_scope=["authentication", "file_activity", "process_activity", "device_activity"])).status_code == 201
    created = endpoint_db_session.query(EndpointRequest).count()

    for bad in (["unknown_category"], ["keystrokes"], ["screenshots"], ["passwords"], ["clipboard"], ["authentication", "keystrokes"], [], [""]):
        r = user.post("/api/endpoint-requests", json=_body(requested_scope=bad))
        assert r.status_code == 422, bad
    assert endpoint_db_session.query(EndpointRequest).count() == created  # nothing was stored for rejected requests

    no_consent = _body(consent_acknowledged=False)
    missing = _body()
    del missing["consent_acknowledged"]
    assert user.post("/api/endpoint-requests", json=no_consent).status_code == 422
    assert user.post("/api/endpoint-requests", json=missing).status_code == 422
    assert user.post("/api/endpoint-requests", json=_body(consent_acknowledged="maybe")).status_code == 422
    assert endpoint_db_session.query(EndpointRequest).count() == created


# ============================================================================
# Test 7 - authentication and rate limits
# ============================================================================


class _Clock:
    def __init__(self):
        self.now = 5000.0

    def __call__(self):
        return self.now


@pytest.fixture()
def clock():
    c = _Clock()
    limiters = [rate_limit.login_failures_pair, rate_limit.login_failures_ip, rate_limit.login_failures_user, rate_limit.known_good_logins]
    for lim in limiters:
        lim.set_clock(c)
    yield c
    import time

    for lim in limiters:
        lim.set_clock(time.monotonic)


def _login(c, user, password, ip):
    return c.post("/api/auth/login", json={"username": user, "password": password}, headers={"X-Forwarded-For": ip}).status_code


def test_7_rate_limits(anon_client, endpoint_db_session, clock, monkeypatch):
    dashboard_auth.create_user(endpoint_db_session, TEST_DASHBOARD_USER, TEST_DASHBOARD_PASSWORD)
    n = settings.dashboard_login_max_failures
    window = settings.dashboard_login_lockout_seconds

    # --- forged X-Forwarded-For is IGNORED while no proxy is trusted ---
    assert [_login(anon_client, TEST_DASHBOARD_USER, "wrong-password-1", f"10.1.1.{i}") for i in range(n + 1)] == [401] * n + [429]
    rate_limit.reset_all()

    # --- with the direct peer trusted as a proxy, addresses are distinguished ---
    monkeypatch.setattr(settings, "trusted_proxies", "testclient")
    # per username + IP
    assert [_login(anon_client, TEST_DASHBOARD_USER, "wrong-password-1", "198.51.100.9") for _ in range(n)] == [401] * n
    assert _login(anon_client, TEST_DASHBOARD_USER, TEST_DASHBOARD_PASSWORD, "198.51.100.9") == 429  # even the right password, from the attacker's address
    assert _login(anon_client, TEST_DASHBOARD_USER, TEST_DASHBOARD_PASSWORD, "203.0.113.7") == 200  # the real admin elsewhere is unaffected
    # per IP, changing usernames does not help
    monkeypatch.setattr(settings, "dashboard_login_max_failures_per_ip", 8)
    codes = [_login(anon_client, f"spray{i}", "wrong-password-1", "192.0.2.50") for i in range(10)]
    assert codes == [401] * 8 + [429] * 2

    # --- window expiry ---
    clock.now += window - 1
    assert _login(anon_client, TEST_DASHBOARD_USER, TEST_DASHBOARD_PASSWORD, "198.51.100.9") == 429
    clock.now += 2
    assert _login(anon_client, TEST_DASHBOARD_USER, TEST_DASHBOARD_PASSWORD, "198.51.100.9") == 200  # expired on its own
    assert _login(anon_client, "spray-again", "wrong-password-1", "192.0.2.50") == 401

    # --- recovery: an admin clears a throttled user (no password / session change) ---
    admin = _client_for(TEST_DASHBOARD_USER, TEST_DASHBOARD_PASSWORD)
    _signup(anon_client, "locked-user")
    for _ in range(n):
        _login(anon_client, "locked-user", "wrong-password-1", "198.51.100.77")
    assert _login(anon_client, "locked-user", PW, "198.51.100.77") == 429
    assert admin.post("/api/admin/auth/unlock", json={"username": "locked-user"}).json()["counters_cleared"] >= 1
    assert _login(anon_client, "locked-user", PW, "198.51.100.77") == 200
    assert _login(anon_client, "locked-user", "still-wrong-pw-1", "198.51.100.78") == 401  # unlock did not change the password
