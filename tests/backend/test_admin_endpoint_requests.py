"""Phase 17 stage 2: admin request management, audit, revocation."""

import threading
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.models.dashboard_auth import DashboardUser
from app.models.endpoint import EndpointRecord
from app.models.enrollment import AuditEvent, EndpointRequest, EnrollmentAuthorization, Notification
from app.security import agent_auth
from app.services import admin_request_service
from tests.backend.test_endpoint_requests import PASSWORD, _login_client, _register, _request_body


@pytest.fixture()
def alice(anon_client):
    _register(anon_client, "alice")
    return _login_client("alice")


@pytest.fixture()
def pending(alice):
    return alice.post("/api/endpoint-requests", json=_request_body(justification="Lab PC for research")).json()


def _audit_actions(db, request_id):
    return [a.action for a in db.query(AuditEvent).filter_by(request_id=request_id).order_by(AuditEvent.id)]


# --- listing / details ------------------------------------------------------


def test_admin_lists_and_filters_requests_with_requester_details(client, alice, pending):
    body = client.get("/api/admin/endpoint-requests").json()
    assert body["total"] == 1 and body["counts"]["PENDING"] == 1 and body["counts"]["APPROVED"] == 0
    item = body["items"][0]
    assert item["requester_email"] == "alice@example.org" and item["requester_full_name"] == "Test Person"
    assert item["organization"] == "Example University" and item["department"] == "Security Lab"
    assert item["justification"] == "Lab PC for research"
    assert item["requested_scope"] == ["authentication", "process_activity"]
    assert client.get("/api/admin/endpoint-requests", params={"status": "APPROVED"}).json()["total"] == 0
    assert client.get("/api/admin/endpoint-requests", params={"q": "ALICE@example"}).json()["total"] == 1
    assert client.get("/api/admin/endpoint-requests", params={"q": "nobody"}).json()["total"] == 0
    assert client.get("/api/admin/endpoint-requests", params={"status": "BOGUS"}).status_code == 422


def test_admin_detail_includes_audit_history(client, pending):
    d = client.get(f"/api/admin/endpoint-requests/{pending['id']}").json()
    assert [h["action"] for h in d["audit_history"]] == ["request.created"]
    assert client.get("/api/admin/endpoint-requests/nope").status_code == 404


# --- approve / reject -------------------------------------------------------


def test_approve_records_decision_audit_and_notifies(client, alice, pending, endpoint_db_session):
    r = client.post(f"/api/admin/endpoint-requests/{pending['id']}/approve", json={"note": "ok"})
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "APPROVED" and d["decided_by"] == "test-operator"
    assert d["approved_scope"] == ["authentication", "process_activity"]
    assert d["requested_scope"] == ["authentication", "process_activity"]  # request is preserved
    assert d["organization"] == "Example University" and d["justification"] == "Lab PC for research"
    assert d["approval_expires_at"] is not None
    assert _audit_actions(endpoint_db_session, pending["id"]) == ["request.created", "request.approved"]
    assert endpoint_db_session.query(Notification).filter_by(username="alice", kind="request.approved").count() == 1
    # Stage 2 does NOT issue enrollment tokens.
    assert endpoint_db_session.query(EnrollmentAuthorization).count() == 0
    assert alice.get(f"/api/endpoint-requests/{pending['id']}").json()["status"] == "APPROVED"


def test_approve_can_narrow_but_not_widen_scope(client, pending):
    ok = client.post(f"/api/admin/endpoint-requests/{pending['id']}/approve", json={"approved_scope": ["authentication"]})
    assert ok.status_code == 200 and ok.json()["approved_scope"] == ["authentication"]


@pytest.mark.parametrize("scope", [["file_activity"], ["authentication", "device_activity"], ["keystrokes"], []])
def test_approve_rejects_scope_outside_request(client, alice, scope):
    req = alice.post("/api/endpoint-requests", json=_request_body(requested_scope=["authentication", "process_activity"])).json()
    r = client.post(f"/api/admin/endpoint-requests/{req['id']}/approve", json={"approved_scope": scope})
    if scope == []:  # empty = "use the requested scope"
        assert r.status_code == 200
    else:
        assert r.status_code == 422


def test_reject_requires_reason_and_records_it(client, alice, pending, endpoint_db_session):
    url = f"/api/admin/endpoint-requests/{pending['id']}/reject"
    assert client.post(url, json={}).status_code == 422
    assert client.post(url, json={"reason": ""}).status_code == 422
    assert client.post(url, json={"reason": "      "}).status_code == 422  # whitespace is not a reason
    r = client.post(url, json={"reason": "Not an authorized machine"})
    assert r.status_code == 200 and r.json()["status"] == "REJECTED"
    assert r.json()["status_reason"] == "Not an authorized machine"
    assert "request.rejected" in _audit_actions(endpoint_db_session, pending["id"])
    note = endpoint_db_session.query(Notification).filter_by(username="alice", kind="request.rejected").one()
    assert "Not an authorized machine" in note.message


def test_invalid_transitions_return_409(client, pending):
    base = f"/api/admin/endpoint-requests/{pending['id']}"
    assert client.post(f"{base}/reject", json={"reason": "no thanks"}).status_code == 200
    assert client.post(f"{base}/approve", json={}).status_code == 409  # rejected stays rejected
    assert client.post(f"{base}/reject", json={"reason": "again"}).status_code == 409
    assert client.post(f"{base}/revoke", json={}).status_code == 409  # nothing to revoke


def test_admin_cannot_decide_own_request(client):
    own = client.post("/api/endpoint-requests", json=_request_body(organization="Ops Org")).json()
    assert client.post(f"/api/admin/endpoint-requests/{own['id']}/approve", json={}).status_code == 403
    assert client.post(f"/api/admin/endpoint-requests/{own['id']}/reject", json={"reason": "self"}).status_code == 403


def test_approval_window_expires(client, alice, pending, endpoint_db_session):
    client.post(f"/api/admin/endpoint-requests/{pending['id']}/approve", json={})
    req = endpoint_db_session.get(EndpointRequest, pending["id"])
    req.approval_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    endpoint_db_session.commit()
    assert client.get(f"/api/admin/endpoint-requests/{pending['id']}").json()["status"] == "EXPIRED"
    assert "request.expired" in _audit_actions(endpoint_db_session, pending["id"])
    assert client.post(f"/api/admin/endpoint-requests/{pending['id']}/revoke", json={}).status_code == 409


# --- revocation -------------------------------------------------------------


def test_revoke_approved_request(client, alice, pending, endpoint_db_session):
    base = f"/api/admin/endpoint-requests/{pending['id']}"
    client.post(f"{base}/approve", json={})
    r = client.post(f"{base}/revoke", json={"reason": "changed my mind"})
    assert r.status_code == 200 and r.json()["status"] == "REVOKED"
    assert "request.revoked" in _audit_actions(endpoint_db_session, pending["id"])
    assert endpoint_db_session.query(Notification).filter_by(username="alice", kind="request.revoked").count() == 1


def test_revoking_an_installed_request_kills_the_endpoint_credential(client, anon_client, alice, pending, endpoint_db_session, monkeypatch):
    """ENROLLED is normally set by redemption; here it is staged directly
    to test the revoke path against a real enrolled endpoint."""
    base = f"/api/admin/endpoint-requests/{pending['id']}"
    client.post(f"{base}/approve", json={})
    monkeypatch.setattr(agent_auth.settings, "agent_api_key", "enroll-key")
    enrolled = anon_client.post("/api/endpoints/register", json={"display_name": "ALICE-PC"}, headers={"X-Agent-Api-Key": "enroll-key"}).json()
    h = {"X-Endpoint-Id": enrolled["endpoint_id"], "X-Agent-Credential": enrolled["agent_credential"]}
    assert anon_client.post("/api/ingest/events", json={"log_name": "Security", "events": []}, headers=h).status_code == 200

    req = endpoint_db_session.get(EndpointRequest, pending["id"])
    req.status, req.endpoint_id, req.installed_at = "ENROLLED", enrolled["endpoint_id"], datetime.now(timezone.utc)
    endpoint_db_session.commit()

    r = client.post(f"{base}/revoke", json={"reason": "lost laptop"})
    assert r.status_code == 200 and r.json()["status"] == "REVOKED"
    # The credential no longer works: no further uploads or heartbeats.
    assert anon_client.post("/api/ingest/events", json={"log_name": "Security", "events": []}, headers=h).status_code == 401
    assert anon_client.post("/api/endpoints/heartbeat", headers=h).status_code == 401
    rec = endpoint_db_session.get(EndpointRecord, enrolled["endpoint_id"])
    endpoint_db_session.refresh(rec)
    assert rec.credential_hash is None and rec.status == "revoked"
    assert any("credential_revoked=True" in (a.detail or "") for a in endpoint_db_session.query(AuditEvent).filter_by(action="request.revoked"))


# --- authorization ----------------------------------------------------------


def test_normal_user_cannot_use_any_admin_action(alice, anon_client):
    other = alice.post("/api/endpoint-requests", json=_request_body()).json()
    base = f"/api/admin/endpoint-requests/{other['id']}"
    assert alice.get("/api/admin/endpoint-requests").status_code == 403
    assert alice.get(base).status_code == 403
    assert alice.post(f"{base}/approve", json={}).status_code == 403  # no self-approval
    assert alice.post(f"{base}/reject", json={"reason": "x y z"}).status_code == 403
    assert alice.post(f"{base}/revoke", json={}).status_code == 403
    assert alice.get("/api/admin/audit").status_code == 403
    assert alice.post("/api/admin/auth/unlock", json={"username": "test-operator"}).status_code == 403
    assert anon_client.get("/api/admin/endpoint-requests").status_code == 401
    assert alice.get(base).status_code == 403 and alice.get(f"/api/endpoint-requests/{other['id']}").status_code == 200


def test_another_user_cannot_see_the_request_or_its_decision(client, alice, anon_client, pending):
    _register(anon_client, "bob")
    bob = _login_client("bob")
    client.post(f"/api/admin/endpoint-requests/{pending['id']}/approve", json={})
    assert bob.get(f"/api/endpoint-requests/{pending['id']}").status_code == 404
    assert bob.get("/api/endpoint-requests/my").json() == []


def test_audit_endpoint_lists_actions(client, pending):
    client.post(f"/api/admin/endpoint-requests/{pending['id']}/reject", json={"reason": "no reason"})
    rows = client.get("/api/admin/audit", params={"request_id": pending["id"]}).json()
    assert [r["action"] for r in rows] == ["request.rejected", "request.created"]
    assert all("token" not in (r["detail"] or "").lower() for r in rows)


# --- concurrency ------------------------------------------------------------


def test_concurrent_decisions_have_exactly_one_winner(tmp_path):
    """Two admins race to decide one request on a real (file) database."""
    from app.db.database import Base
    from app.models import dashboard_auth, enrollment  # noqa: F401

    engine = create_engine(f"sqlite:///{tmp_path / 'race.db'}", connect_args={"check_same_thread": False, "timeout": 15})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    now = datetime.now(timezone.utc)
    with Session() as s:
        for name in ("a1", "a2", "user1"):
            s.add(DashboardUser(username=name, password_hash="x", created_at=now, role="user" if name == "user1" else "admin"))
        s.add(EndpointRequest(id="r1", username="user1", organization="Org", requested_scope="authentication",
                              consent_version="v", consent_acknowledged_at=now, status="PENDING", created_at=now, updated_at=now))
        s.commit()

    results = []

    def decide(admin_name, action):
        with Session() as s:
            admin = s.get(DashboardUser, admin_name)
            try:
                if action == "approve":
                    admin_request_service.approve(s, admin, "r1", approved_scope=None, note=None)
                else:
                    admin_request_service.reject(s, admin, "r1", reason="racing")
                results.append(("ok", action))
            except HTTPException as exc:
                results.append((exc.status_code, action))

    threads = [threading.Thread(target=decide, args=("a1", "approve")), threading.Thread(target=decide, args=("a2", "reject"))]
    [t.start() for t in threads]
    [t.join(30) for t in threads]
    assert sorted(str(r[0]) for r in results) == ["409", "ok"], results
    with Session() as s:
        assert s.query(AuditEvent).filter(AuditEvent.action.in_(["request.approved", "request.rejected"])).count() == 1
    engine.dispose()
