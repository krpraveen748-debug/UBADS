"""Phase 17 stage 4 (4A-4C): one-time enrollment codes - minting, atomic redemption,
scope binding, revocation, logging hygiene and compatibility with existing agents.

All tests use isolated in-memory / temp-file SQLite databases and a tiny stub
installer; no real endpoint, credential or event is involved."""

import logging
import re
import threading
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.main import app
from app.models.dashboard_auth import DashboardUser
from app.models.endpoint import EndpointRecord
from app.models.enrollment import (
    AuditEvent,
    EndpointRequest,
    EnrollmentAuthorization,
    Notification,
)
from app.security import agent_auth, rate_limit
from app.services import enrollment_service
from tests.backend.test_endpoint_requests import _login_client, _register, _request_body

STUB = b"MZ-stub-installer-bytes"
REDEEM = "/api/agent/enrollment/redeem"
UUID_A = "11111111-1111-4111-8111-111111111111"
UUID_B = "22222222-2222-4222-8222-222222222222"


@pytest.fixture()
def installer(tmp_path, monkeypatch):
    path = tmp_path / "UBADS-Agent-Setup.exe"
    path.write_bytes(STUB)
    monkeypatch.setattr(settings, "installer_path", str(path))
    return path


@pytest.fixture()
def agent_http(anon_client):
    """An anonymous client, as the Windows agent is (no dashboard session).
    Depends on anon_client ONLY so the isolated in-memory database overrides are
    always installed - a bare TestClient(app) would otherwise reach the real DB."""
    return TestClient(app)


@pytest.fixture()
def alice(anon_client):
    _register(anon_client, "alice")
    return _login_client("alice")


def _approved(client, user, scope=("authentication", "process_activity"), approve_scope=None):
    rid = user.post("/api/endpoint-requests", json=_request_body(requested_scope=list(scope))).json()["id"]
    body = {"approved_scope": list(approve_scope)} if approve_scope else {}
    assert client.post(f"/api/admin/endpoint-requests/{rid}/approve", json=body).status_code == 200
    return rid


def _mint(user, rid):
    r = user.post(f"/api/endpoint-requests/{rid}/enrollment-package")
    assert r.status_code == 200, r.text
    return re.search(r'filename="UBADS-Agent-Setup--(.+)\.exe"', r.headers["content-disposition"]).group(1), r


def _redeem(agent, code, **over):
    body = {"code": code, "display_name": "ALICE-PC", "operating_system": "Windows 11", "agent_version": "0.1.0"}
    body.update(over)
    return agent.post(REDEEM, json=body)


def _headers(data):
    return {"X-Endpoint-Id": data["endpoint_id"], "X-Agent-Credential": data["agent_credential"]}


# One REAL Windows event id per category - the server derives the category from the id (Stage 4G).
_CATEGORY_EVENT_ID = {"authentication": 4624, "file_activity": 4663, "process_activity": 4688, "device_activity": 6416}


def _event(category="authentication", record_id=1):
    return {
        "event_id": _CATEGORY_EVENT_ID[category], "event_type": "successful_logon", "event_category": category,
        "timestamp": "2026-01-01T00:00:00.000000Z", "computer_name": "ENROLL-TEST-FIXTURE",
        "username": "fixture", "event_record_id": record_id,
    }


# ============================================================ minting (4B)


def test_owner_gets_the_installer_under_a_code_filename_and_only_a_hash_is_stored(client, alice, installer, endpoint_db_session):
    rid = _approved(client, alice)
    code, r = _mint(alice, rid)
    assert r.content == STUB and r.headers["cache-control"] == "no-store"
    parsed = enrollment_service.parse_code(code)
    assert parsed and parsed.base_url == settings.resolved_public_base_url  # from config, not from the request

    row = endpoint_db_session.query(EnrollmentAuthorization).one()
    assert row.token_hash == enrollment_service.hash_secret(parsed.secret) and len(row.token_hash) == 64
    assert row.username == "alice" and row.organization == "Example University" and row.request_id == rid
    assert row.scope == "authentication,process_activity" and row.redeemed_at is None
    assert endpoint_db_session.get(EndpointRequest, rid).status == "ENROLLMENT_PENDING"
    # the secret (and the whole code) appears nowhere in the database
    dump = ""
    for table in ("enrollment_authorizations", "endpoint_requests", "audit_events", "notifications", "endpoints"):
        dump += str(endpoint_db_session.execute(text(f"select * from {table}")).fetchall())
    assert parsed.secret not in dump and code not in dump
    assert row.expires_at.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc) <= timedelta(minutes=settings.enrollment_code_ttl_minutes)
    assert endpoint_db_session.query(AuditEvent).filter_by(action="enrollment.code_issued").count() == 1


def test_mint_is_denied_unless_the_owner_has_an_approved_request(client, anon_client, alice, installer):
    pending = alice.post("/api/endpoint-requests", json=_request_body()).json()["id"]
    rejected = alice.post("/api/endpoint-requests", json=_request_body()).json()["id"]
    client.post(f"/api/admin/endpoint-requests/{rejected}/reject", json={"reason": "no thanks"})
    revoked = _approved(client, alice)
    client.post(f"/api/admin/endpoint-requests/{revoked}/revoke", json={})
    for rid in (pending, rejected, revoked):
        assert alice.post(f"/api/endpoint-requests/{rid}/enrollment-package").status_code == 403
    approved = _approved(client, alice)
    _register(anon_client, "mallory")
    mallory = _login_client("mallory")
    assert mallory.post(f"/api/endpoint-requests/{approved}/enrollment-package").status_code == 404  # not even confirmed to exist
    assert TestClient(app).post(f"/api/endpoint-requests/{approved}/enrollment-package").status_code == 401
    assert alice.get(f"/api/endpoint-requests/{approved}/enrollment-package").status_code == 405  # never a GET


def test_mint_needs_a_configured_server_address_and_an_installer(client, alice, installer, monkeypatch, tmp_path):
    rid = _approved(client, alice)
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "public_base_url", "")
    assert alice.post(f"/api/endpoint-requests/{rid}/enrollment-package").status_code == 503
    monkeypatch.setattr(settings, "public_base_url", "http://insecure.example")
    assert alice.post(f"/api/endpoint-requests/{rid}/enrollment-package").status_code == 503  # no http:// in production
    monkeypatch.setattr(settings, "public_base_url", "https://ubads.example.com/")
    ok = _mint(alice, rid)[0]
    assert enrollment_service.parse_code(ok).base_url == "https://ubads.example.com"
    monkeypatch.setattr(settings, "environment", "local")
    monkeypatch.setattr(settings, "installer_path", str(tmp_path / "missing.exe"))
    assert alice.post(f"/api/endpoint-requests/{rid}/enrollment-package").status_code == 503


def test_a_forged_host_header_cannot_change_where_the_agent_enrolls(client, alice, installer):
    rid = _approved(client, alice)
    r = alice.post(f"/api/endpoint-requests/{rid}/enrollment-package", headers={"Host": "evil.example", "X-Forwarded-Host": "evil.example"})
    code = re.search(r'filename="UBADS-Agent-Setup--(.+)\.exe"', r.headers["content-disposition"]).group(1)
    assert "evil" not in enrollment_service.parse_code(code).base_url


def test_minting_again_supersedes_the_old_code_and_never_consumes_anything(client, alice, installer, agent_http, endpoint_db_session):
    rid = _approved(client, alice)
    first, _ = _mint(alice, rid)
    second, _ = _mint(alice, rid)  # a refresh / second click
    assert first != second
    old = _redeem(agent_http, first)
    assert old.status_code == 410 and old.json()["detail"]["code"] == "superseded"
    assert endpoint_db_session.query(EnrollmentAuthorization).filter(EnrollmentAuthorization.redeemed_at.isnot(None)).count() == 0
    assert _redeem(agent_http, second).status_code == 200  # the newest one still works
    assert endpoint_db_session.query(AuditEvent).filter_by(action="enrollment.code_superseded").count() == 1


def test_mint_is_rate_limited_per_user(client, alice, installer, monkeypatch):
    monkeypatch.setattr(settings, "enrollment_mint_max_per_hour", 3)
    rid = _approved(client, alice)
    assert [alice.post(f"/api/endpoint-requests/{rid}/enrollment-package").status_code for _ in range(4)] == [200, 200, 200, 429]


# ============================================================ redemption (4C)


def test_valid_redemption_provisions_a_unique_credential_bound_to_the_approved_scope(client, alice, installer, agent_http, endpoint_db_session):
    rid = _approved(client, alice, approve_scope=["authentication"])
    code, _ = _mint(alice, rid)
    r = _redeem(agent_http, code, endpoint_id=UUID_A)
    assert r.status_code == 200
    d = r.json()
    assert d["endpoint_id"] == UUID_A and d["monitoring_scope"] == ["authentication"] and len(d["agent_credential"]) >= 40

    ep = endpoint_db_session.get(EndpointRecord, UUID_A)
    assert ep.monitoring_scope == "authentication" and ep.enrolled_request_id == rid
    assert ep.credential_hash == agent_auth.hash_agent_credential(d["agent_credential"]) and d["agent_credential"] not in str(ep.credential_hash)
    req = endpoint_db_session.get(EndpointRequest, rid)
    assert req.status == "ENROLLED" and req.endpoint_id == UUID_A and req.installed_at is not None
    row = endpoint_db_session.query(EnrollmentAuthorization).one()
    assert row.redeemed_at is not None and row.redeemed_endpoint_id == UUID_A
    assert endpoint_db_session.query(AuditEvent).filter_by(action="enrollment.redeemed").one().target == UUID_A
    assert endpoint_db_session.query(Notification).filter_by(username="alice", kind="request.enrolled").count() == 1
    assert alice.get(f"/api/endpoint-requests/{rid}").json()["endpoint_connection_status"] == "online"  # status vs connectivity are separate fields


def test_enrolled_agent_can_register_heartbeat_and_ingest_but_only_within_scope(client, alice, installer, agent_http):
    rid = _approved(client, alice, approve_scope=["authentication"])
    data = _redeem(agent_http, _mint(alice, rid)[0]).json()
    h = _headers(data)
    assert agent_http.post("/api/endpoints/register", json={"display_name": "ALICE-PC2"}, headers=h).status_code == 200
    assert agent_http.post("/api/endpoints/heartbeat", headers=h).status_code == 200
    ok = agent_http.post("/api/ingest/events", json={"log_name": "Security", "events": [_event("authentication", 1)]}, headers=h).json()
    assert ok["accepted"] == 1 and ok["out_of_scope"] == 0
    out = agent_http.post(
        "/api/ingest/events",
        json={"log_name": "Security", "events": [_event("file_activity", 2), _event("process_activity", 3), _event("authentication", 4)]},
        headers=h,
    ).json()
    assert out["accepted"] == 1 and out["out_of_scope"] == 2  # file/process were never approved
    stored = client.get("/api/events", params={"endpoint_id": data["endpoint_id"]}).json()
    assert sorted(e["event_category"] for e in stored) == ["authentication", "authentication"]


def test_codes_for_different_requests_yield_distinct_endpoints_and_credentials(client, alice, installer, agent_http):
    a = _redeem(agent_http, _mint(alice, _approved(client, alice))[0]).json()
    b = _redeem(agent_http, _mint(alice, _approved(client, alice))[0]).json()
    assert a["endpoint_id"] != b["endpoint_id"] and a["agent_credential"] != b["agent_credential"]
    wrong = {"X-Endpoint-Id": a["endpoint_id"], "X-Agent-Credential": b["agent_credential"]}
    assert agent_http.post("/api/endpoints/heartbeat", headers=wrong).status_code == 401  # credentials are not interchangeable


@pytest.mark.parametrize("bad", ["", "nonsense", "ubads1.aaa.bbb", "ubads1." + "x" * 30 + "." + "y" * 43, "ubads2.aHR0cDovL3g." + "A" * 43, "a.b.c.d"])
def test_invalid_or_malformed_codes_are_rejected_identically(agent_http, bad):
    r = _redeem(agent_http, bad) if bad else agent_http.post(REDEEM, json={"code": ""})
    assert r.status_code in (401, 422)
    if r.status_code == 401:
        assert r.json()["detail"]["code"] == "invalid_code"


def test_a_well_formed_but_unknown_code_matches_the_malformed_response(agent_http, client, alice, installer):
    known, _ = _mint(alice, _approved(client, alice))
    parsed = enrollment_service.parse_code(known)
    unknown = enrollment_service.build_code(parsed.base_url, "A" * 43)
    assert _redeem(agent_http, unknown).json() == _redeem(agent_http, "garbage").json()


def test_expired_code_is_rejected_and_nothing_is_created(client, alice, installer, agent_http, endpoint_db_session):
    rid = _approved(client, alice)
    code, _ = _mint(alice, rid)
    endpoint_db_session.query(EnrollmentAuthorization).update({"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)})
    endpoint_db_session.commit()
    r = _redeem(agent_http, code)
    assert r.status_code == 410 and r.json()["detail"]["code"] == "expired"
    assert endpoint_db_session.query(EndpointRecord).count() == 0
    assert endpoint_db_session.get(EndpointRequest, rid).status == "ENROLLMENT_PENDING"
    # the user is not stuck: a fresh package works once the stale code is noticed
    assert alice.get(f"/api/endpoint-requests/{rid}").json()["status"] in ("ENROLLMENT_PENDING", "APPROVED")
    client.get("/api/admin/endpoint-requests")  # triggers lazy expiry
    assert endpoint_db_session.get(EndpointRequest, rid).status == "APPROVED"
    assert _redeem(agent_http, _mint(alice, rid)[0]).status_code == 200


def test_a_used_code_cannot_be_replayed(client, alice, installer, agent_http, endpoint_db_session):
    code, _ = _mint(alice, _approved(client, alice))
    assert _redeem(agent_http, code).status_code == 200
    again = _redeem(agent_http, code)
    assert again.status_code == 409 and again.json()["detail"]["code"] == "already_used"
    assert endpoint_db_session.query(EndpointRecord).count() == 1  # no second credential


def test_revoked_request_cannot_redeem_and_the_code_is_not_consumed(client, alice, installer, agent_http, endpoint_db_session):
    rid = _approved(client, alice)
    code, _ = _mint(alice, rid)
    assert client.post(f"/api/admin/endpoint-requests/{rid}/revoke", json={"reason": "policy"}).status_code == 200
    r = _redeem(agent_http, code)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "revoked"
    row = endpoint_db_session.query(EnrollmentAuthorization).one()
    assert row.revoked_at is not None and row.redeemed_at is None
    assert endpoint_db_session.query(EndpointRecord).count() == 0
    assert "codes_revoked=1" in endpoint_db_session.query(AuditEvent).filter_by(action="request.revoked").one().detail


def test_revoking_after_enrollment_stops_uploads(client, alice, installer, agent_http):
    rid = _approved(client, alice)
    data = _redeem(agent_http, _mint(alice, rid)[0]).json()
    h = _headers(data)
    assert agent_http.post("/api/ingest/events", json={"log_name": "Security", "events": []}, headers=h).status_code == 200
    assert client.post(f"/api/admin/endpoint-requests/{rid}/revoke", json={"reason": "lost laptop"}).json()["status"] == "REVOKED"
    assert agent_http.post("/api/ingest/events", json={"log_name": "Security", "events": [_event()]}, headers=h).status_code == 401
    assert agent_http.post("/api/endpoints/heartbeat", headers=h).status_code == 401


def test_status_flipped_to_revoked_between_checks_loses_the_race_without_burning_the_code(client, alice, installer, agent_http, endpoint_db_session):
    rid = _approved(client, alice)
    code, _ = _mint(alice, rid)
    endpoint_db_session.get(EndpointRequest, rid).status = "REVOKED"  # as if an admin revoked just now
    endpoint_db_session.commit()
    assert _redeem(agent_http, code).status_code == 403
    assert endpoint_db_session.query(EnrollmentAuthorization).one().redeemed_at is None


def test_wrong_user_or_wrong_organization_on_the_authorization_is_refused(client, alice, installer, agent_http, endpoint_db_session):
    rid = _approved(client, alice)
    code, _ = _mint(alice, rid)
    row = endpoint_db_session.query(EnrollmentAuthorization).one()
    row.username = "someone-else"
    endpoint_db_session.commit()
    assert _redeem(agent_http, code).json()["detail"]["code"] == "request_mismatch"
    row.username, row.organization = "alice", "Another Organization"
    endpoint_db_session.commit()
    assert _redeem(agent_http, code).json()["detail"]["code"] == "request_mismatch"
    row.organization = "Example University"
    endpoint_db_session.commit()
    endpoint_db_session.delete(endpoint_db_session.get(DashboardUser, "alice"))  # owner account removed
    endpoint_db_session.commit()
    assert _redeem(agent_http, code).json()["detail"]["code"] == "account_unavailable"
    assert endpoint_db_session.query(EndpointRecord).count() == 0 and row.redeemed_at is None


def test_scope_cannot_be_widened_by_the_agent_or_by_tampering(client, alice, installer, agent_http, endpoint_db_session):
    rid = _approved(client, alice, approve_scope=["authentication"])
    code, _ = _mint(alice, rid)
    # the agent tries to ask for more: those fields are simply ignored
    tamper = _redeem(agent_http, code, scope=["file_activity", "keystrokes"], monitoring_scope="authentication,file_activity", username="admin", organization="Other")
    # (body fields beyond the schema are ignored; this first attempt succeeds with the APPROVED scope)
    assert tamper.status_code == 200 and tamper.json()["monitoring_scope"] == ["authentication"]
    assert endpoint_db_session.get(EndpointRecord, tamper.json()["endpoint_id"]).monitoring_scope == "authentication"

    # server-side tampering: the pinned scope no longer equals the approved scope
    rid2 = _approved(client, alice, approve_scope=["authentication"])
    code2, _ = _mint(alice, rid2)
    endpoint_db_session.query(EnrollmentAuthorization).filter_by(request_id=rid2).update({"scope": "authentication,file_activity"})
    endpoint_db_session.commit()
    assert _redeem(agent_http, code2).json()["detail"]["code"] == "scope_mismatch"
    # ...or the approved scope grows past what was requested
    rid3 = _approved(client, alice, scope=("authentication",))
    code3, _ = _mint(alice, rid3)
    endpoint_db_session.query(EndpointRequest).filter_by(id=rid3).update({"approved_scope": "authentication,device_activity"})
    endpoint_db_session.query(EnrollmentAuthorization).filter_by(request_id=rid3).update({"scope": "authentication,device_activity"})
    endpoint_db_session.commit()
    assert _redeem(agent_http, code3).json()["detail"]["code"] == "scope_mismatch"


def test_an_existing_endpoint_id_is_never_taken_over_and_the_code_survives(client, alice, installer, agent_http, endpoint_db_session, monkeypatch):
    monkeypatch.setattr(agent_auth.settings, "agent_api_key", "enroll-key")
    legacy = agent_http.post("/api/endpoints/register", json={"endpoint_id": UUID_A, "display_name": "LEGACY"}, headers={"X-Agent-Api-Key": "enroll-key"}).json()
    code, _ = _mint(alice, _approved(client, alice))
    r = _redeem(agent_http, code, endpoint_id=UUID_A)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "endpoint_id_in_use"
    assert endpoint_db_session.query(EnrollmentAuthorization).one().redeemed_at is None  # rolled back, not burned
    still = endpoint_db_session.get(EndpointRecord, UUID_A)
    assert still.display_name == "LEGACY" and still.monitoring_scope is None
    assert agent_http.post("/api/endpoints/heartbeat", headers=_headers(legacy)).status_code == 200  # legacy endpoint untouched
    assert _redeem(agent_http, code, endpoint_id="not-a-uuid").status_code == 422
    assert _redeem(agent_http, code, endpoint_id=UUID_B).status_code == 200  # same code, new id


def test_failed_redemptions_are_rate_limited_per_ip(client, alice, installer, agent_http, monkeypatch):
    monkeypatch.setattr(settings, "enrollment_redeem_max_failures_per_ip", 4)
    code, _ = _mint(alice, _approved(client, alice))
    assert [_redeem(agent_http, "garbage").status_code for _ in range(4)] == [401] * 4
    blocked = _redeem(agent_http, code)
    assert blocked.status_code == 429 and blocked.json()["detail"]["code"] == "rate_limited" and "retry-after" in blocked.headers
    rate_limit.reset_all()
    assert _redeem(agent_http, code).status_code == 200  # the valid code was never harmed


def test_no_secret_reaches_logs_audit_or_notifications(client, alice, installer, agent_http, endpoint_db_session, caplog):
    with caplog.at_level(logging.DEBUG):
        rid = _approved(client, alice)
        code, _ = _mint(alice, rid)
        secret = enrollment_service.parse_code(code).secret
        _redeem(agent_http, "ubads1.aHR0cDovL3g." + "B" * 43)  # a failed attempt
        data = _redeem(agent_http, code).json()
        _redeem(agent_http, code)  # replay
    blob = caplog.text
    for sensitive in (code, secret, enrollment_service.hash_secret(secret), data["agent_credential"], agent_auth.hash_agent_credential(data["agent_credential"])):
        assert sensitive not in blob
    stored = str(endpoint_db_session.execute(text("select detail, target, actor from audit_events")).fetchall()) + str(
        endpoint_db_session.execute(text("select title, message from notifications")).fetchall()
    )
    for sensitive in (code, secret, data["agent_credential"]):
        assert sensitive not in stored


def test_the_redemption_route_needs_no_login_and_a_dashboard_session_grants_nothing(client, alice, installer, agent_http):
    code, _ = _mint(alice, _approved(client, alice))
    # an unauthenticated agent can redeem; the admin/user session headers play no role
    assert _redeem(TestClient(app), "garbage").status_code == 401
    admin_headers = {"Authorization": client.headers["Authorization"]}
    assert TestClient(app).post(REDEEM, json={"code": "garbage"}, headers=admin_headers).status_code == 401
    assert _redeem(TestClient(app), code).status_code == 200


def test_existing_shared_key_enrollment_and_legacy_endpoints_are_unchanged(agent_http, monkeypatch):
    monkeypatch.setattr(agent_auth.settings, "agent_api_key", "enroll-key")
    r = agent_http.post("/api/endpoints/register", json={"display_name": "LEGACY"}, headers={"X-Agent-Api-Key": "enroll-key"})
    assert r.status_code == 200
    h = _headers(r.json())
    assert r.json()["monitoring_scope"] is None
    out = agent_http.post("/api/ingest/events", json={"log_name": "Security", "events": [_event("file_activity", 9), _event("device_activity", 10)]}, headers=h).json()
    assert out["accepted"] == 2 and out["out_of_scope"] == 0  # no scope = no restriction, exactly as before


def test_approval_window_expiry_revokes_outstanding_codes(client, alice, installer, agent_http, endpoint_db_session):
    rid = _approved(client, alice)
    code, _ = _mint(alice, rid)
    endpoint_db_session.get(EndpointRequest, rid).approval_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    endpoint_db_session.commit()
    assert alice.get(f"/api/endpoint-requests/{rid}").json()["status"] in ("ENROLLMENT_PENDING", "EXPIRED")
    client.get("/api/admin/endpoint-requests")
    assert endpoint_db_session.get(EndpointRequest, rid).status == "EXPIRED"
    assert _redeem(agent_http, code).status_code == 403  # revoked with the expiry
    assert alice.post(f"/api/endpoint-requests/{rid}/enrollment-package").status_code == 403


# ============================================================ concurrency


def test_concurrent_redemption_creates_exactly_one_credential(tmp_path, monkeypatch):
    from app.db.database import Base
    from app.models import dashboard_auth, endpoint, enrollment  # noqa: F401

    rate_limit.reset_all()  # this test builds its own database; start from clean limiter state
    stub = tmp_path / "UBADS-Agent-Setup.exe"
    stub.write_bytes(STUB)
    monkeypatch.setattr(settings, "installer_path", str(stub))
    engine = create_engine(f"sqlite:///{tmp_path / 'race.db'}", connect_args={"check_same_thread": False, "timeout": 30})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    now = datetime.now(timezone.utc)
    with Session() as s:
        s.add(DashboardUser(username="racer", password_hash="x", created_at=now, role="user"))
        s.add(EndpointRequest(id="r1", username="racer", organization="Org", requested_scope="authentication", approved_scope="authentication",
                              consent_version="v", consent_acknowledged_at=now, status="APPROVED", created_at=now, updated_at=now,
                              approval_expires_at=now + timedelta(days=1)))
        s.commit()
        user = s.get(DashboardUser, "racer")
        code = enrollment_service.mint_package(s, user, "r1").code

    outcomes, barrier = [], threading.Barrier(8)

    def attempt(n):
        with Session() as s:
            barrier.wait()
            try:
                result = enrollment_service.redeem(s, code=code, display_name=f"PC{n}", operating_system="W", agent_version="t",
                                                   endpoint_id=f"{n:08d}-0000-4000-8000-000000000000", ip="203.0.113.5")
                outcomes.append(("ok", result["endpoint_id"]))
            except HTTPException as exc:
                outcomes.append((exc.status_code, exc.detail["code"]))
            except Exception as exc:  # surfaced in the assertion message, never swallowed
                outcomes.append(("exception", f"{type(exc).__name__}: {str(exc)[:160]}"))

    threads = [threading.Thread(target=attempt, args=(n,)) for n in range(8)]
    [t.start() for t in threads]
    [t.join(60) for t in threads]
    wins = [o for o in outcomes if o[0] == "ok"]
    assert len(outcomes) == 8 and len(wins) == 1, outcomes
    assert all(o[0] == 409 and o[1] == "already_used" for o in outcomes if o[0] != "ok"), outcomes
    with Session() as s:
        assert s.query(EndpointRecord).count() == 1
        assert s.query(EndpointRecord).one().endpoint_id == wins[0][1]
        assert s.query(EnrollmentAuthorization).one().redeemed_endpoint_id == wins[0][1]
        assert s.get(EndpointRequest, "r1").status == "ENROLLED"
        assert s.query(AuditEvent).filter_by(action="enrollment.redeemed").count() == 1
    engine.dispose()


# ============================================================ code format and migration


def test_code_format_round_trip_and_rejection_of_garbage():
    secret = "S" * 43
    code = enrollment_service.build_code("https://ubads.example.com", secret)
    parsed = enrollment_service.parse_code(f"  {code}  ")
    assert parsed.base_url == "https://ubads.example.com" and parsed.secret == secret
    assert all(c.isalnum() or c in "._-" for c in code)  # safe inside a Windows file name
    for bad in (None, "", "x", code.replace("ubads1", "ubads9"), code[:-1], code + "A", code.replace(".", "..", 1)):
        assert enrollment_service.parse_code(bad) is None


# ============================================================ concurrency anomaly (4D.8) regressions


class _Interleave:
    """Wraps a Session and runs `before_request_read` the first time the redemption reads the
    EndpointRequest row - i.e. precisely between 'looked up the code' and 'checked the request'."""

    def __init__(self, session, before_request_read=None, fail_first_commit=False):
        self._s, self._hook, self._fail_commit = session, before_request_read, fail_first_commit

    def get(self, model, key, *a, **k):
        if model is EndpointRequest and self._hook:
            hook, self._hook = self._hook, None
            hook()
        return self._s.get(model, key, *a, **k)

    def commit(self):
        if self._fail_commit:
            self._fail_commit = False
            from sqlalchemy.exc import OperationalError

            raise OperationalError("COMMIT", {}, Exception("database is locked"))
        return self._s.commit()

    def __getattr__(self, name):
        return getattr(self._s, name)


def test_a_loser_that_reads_after_the_winner_committed_still_reports_already_used(client, alice, installer, endpoint_db_session):
    """The interleaving behind the intermittent Stage 4C failure: the code lookup sees an
    unredeemed code, a competing redemption then commits (code redeemed, request ENROLLED),
    and only then does this caller read the request. It must say already_used, not
    request_not_approved."""
    rid = _approved(client, alice)
    code, _ = _mint(alice, rid)

    def winner_commits():
        now = datetime.now(timezone.utc)
        other = sessionmaker(bind=endpoint_db_session.get_bind())()
        other.query(EnrollmentAuthorization).update({"redeemed_at": now, "redeemed_endpoint_id": UUID_B})
        other.query(EndpointRequest).update({"status": "ENROLLED", "endpoint_id": UUID_B})
        other.commit()
        other.close()

    with pytest.raises(HTTPException) as lost:
        enrollment_service.redeem(_Interleave(endpoint_db_session, winner_commits), code=code, display_name="PC", operating_system="W",
                                  agent_version="t", endpoint_id=UUID_A, ip="203.0.113.9")
    assert lost.value.status_code == 409 and lost.value.detail["code"] == "already_used"
    assert endpoint_db_session.query(EndpointRecord).count() == 0  # the loser created nothing


def test_a_database_lock_during_redemption_is_a_retryable_503_that_does_not_consume_the_code(client, alice, installer, endpoint_db_session):
    rid = _approved(client, alice)
    code, _ = _mint(alice, rid)
    flaky = _Interleave(endpoint_db_session, fail_first_commit=True)
    with pytest.raises(HTTPException) as busy:
        enrollment_service.redeem(flaky, code=code, display_name="PC", operating_system="W", agent_version="t", endpoint_id=UUID_A, ip="203.0.113.9")
    assert busy.value.status_code == 503 and busy.value.detail["code"] == "server_busy" and busy.value.headers["Retry-After"]
    endpoint_db_session.expire_all()
    assert endpoint_db_session.query(EnrollmentAuthorization).one().redeemed_at is None  # rolled back: still usable
    assert endpoint_db_session.query(EndpointRecord).count() == 0
    assert endpoint_db_session.get(EndpointRequest, rid).status == "ENROLLMENT_PENDING"
    # ...and the agent's retry, which the 503 invites, succeeds exactly once
    ok = enrollment_service.redeem(endpoint_db_session, code=code, display_name="PC", operating_system="W", agent_version="t", endpoint_id=UUID_A, ip="203.0.113.9")
    assert ok["endpoint_id"] == UUID_A and endpoint_db_session.query(EndpointRecord).count() == 1
