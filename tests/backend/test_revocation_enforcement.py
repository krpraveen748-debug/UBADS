"""Stage 4G / Finding 2: revocation is final on EVERY credential path.

Audit evidence this fixes: after an administrator revoked a request, POST /api/endpoints/register
with the shared enrollment key and the same endpoint id returned 200 and a fresh working credential
(the request still read REVOKED)."""

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from app.core.config import settings
from app.models.endpoint import EndpointRecord
from app.models.enrollment import AuditEvent
from app.security import agent_auth
from app.services import endpoint_identity_service
from tests.backend.test_enrollment_tokens import (  # noqa: F401  (fixtures + helpers shared with the enrollment tests)
    UUID_A,
    UUID_B,
    _approved,
    _event,
    _headers,
    _mint,
    _redeem,
    agent_http,
    alice,
    installer,
)

REGISTER = "/api/endpoints/register"
KEY = "shared-enrollment-key-for-tests"


@pytest.fixture()
def shared_key(monkeypatch):
    monkeypatch.setattr(agent_auth.settings, "agent_api_key", KEY)
    return {"X-Agent-Api-Key": KEY}


def enrolled_by_request(client, alice, agent_http, endpoint_id=UUID_A):
    rid = _approved(client, alice, approve_scope=("authentication",))
    data = _redeem(agent_http, _mint(alice, rid)[0], endpoint_id=endpoint_id).json()
    return rid, data


def revoke_request(client, rid):
    r = client.post(f"/api/admin/endpoint-requests/{rid}/revoke", json={"reason": "audit"})
    assert r.status_code == 200 and r.json()["status"] == "REVOKED"


def ingest(agent_http, headers):
    return agent_http.post("/api/ingest/events", json={"log_name": "Security", "events": [_event("authentication", 1)]}, headers=headers)


# ---------------------------------------------------------------- the audited attack


def test_a_revoked_endpoint_cannot_obtain_a_new_credential_with_the_shared_key(client, alice, installer, agent_http, shared_key, endpoint_db_session):
    rid, data = enrolled_by_request(client, alice, agent_http)
    old = _headers(data)
    assert ingest(agent_http, old).status_code == 200
    revoke_request(client, rid)

    for attempt in range(3):  # and it stays refused
        r = agent_http.post(REGISTER, json={"endpoint_id": UUID_A, "display_name": "RESURRECTED"}, headers=shared_key)
        assert r.status_code == 403, attempt
        assert "agent_credential" not in r.text
    endpoint_db_session.expire_all()
    record = endpoint_db_session.get(EndpointRecord, UUID_A)
    assert record.credential_hash is None and record.status == "revoked" and record.display_name != "RESURRECTED"
    assert agent_http.post("/api/endpoints/heartbeat", headers=old).status_code == 401
    assert ingest(agent_http, old).status_code == 401
    assert client.get(f"/api/admin/endpoint-requests/{rid}").json()["status"] == "REVOKED"
    blocked = endpoint_db_session.query(AuditEvent).filter_by(action="enrollment.legacy_reenroll_blocked").all()
    assert len(blocked) == 3 and all(b.target == UUID_A and b.request_id == rid for b in blocked)


def test_every_credential_path_is_closed_for_a_revoked_endpoint(client, alice, installer, agent_http, shared_key, endpoint_db_session):
    rid, data = enrolled_by_request(client, alice, agent_http)
    old = _headers(data)
    revoke_request(client, rid)
    fresh_code = _mint_new_request_code(client, alice)

    results = {
        "shared-key re-enrol": agent_http.post(REGISTER, json={"endpoint_id": UUID_A}, headers=shared_key).status_code,
        "credentialed metadata refresh": agent_http.post(REGISTER, json={"display_name": "x"}, headers=old).status_code,
        "heartbeat": agent_http.post("/api/endpoints/heartbeat", headers=old).status_code,
        "ingest": ingest(agent_http, old).status_code,
        "redeem a new code AS the revoked id": _redeem(agent_http, fresh_code, endpoint_id=UUID_A).status_code,
    }
    assert results == {"shared-key re-enrol": 403, "credentialed metadata refresh": 401, "heartbeat": 401, "ingest": 401,
                       "redeem a new code AS the revoked id": 409}, results
    endpoint_db_session.expire_all()
    assert endpoint_db_session.get(EndpointRecord, UUID_A).credential_hash is None  # nothing ever re-issued one
    # the unused code survives the refused attempt and works for a brand-new identity
    assert _redeem(agent_http, fresh_code, endpoint_id=UUID_B).status_code == 200


def _mint_new_request_code(client, alice):
    return _mint(alice, _approved(client, alice, approve_scope=("authentication",)))[0]


def test_a_request_linked_endpoint_is_never_enrolled_with_the_shared_key_even_without_the_revoked_flag(client, alice, installer, agent_http, shared_key, endpoint_db_session):
    rid, data = enrolled_by_request(client, alice, agent_http)
    record = endpoint_db_session.get(EndpointRecord, UUID_A)
    record.credential_hash, record.status = None, "registered"  # e.g. credential cleared by some other route
    endpoint_db_session.commit()
    assert agent_http.post(REGISTER, json={"endpoint_id": UUID_A}, headers=shared_key).status_code == 403
    endpoint_db_session.expire_all()
    assert endpoint_db_session.get(EndpointRecord, UUID_A).credential_hash is None


def test_a_revoked_endpoint_cannot_authenticate_even_if_a_credential_hash_reappears(client, alice, installer, agent_http, endpoint_db_session):
    """Defence in depth: status 'revoked' alone blocks authentication (e.g. after a bad restore or edit)."""
    rid, data = enrolled_by_request(client, alice, agent_http)
    old = _headers(data)
    keep_hash = endpoint_db_session.get(EndpointRecord, UUID_A).credential_hash
    revoke_request(client, rid)
    endpoint_db_session.expire_all()
    record = endpoint_db_session.get(EndpointRecord, UUID_A)
    record.credential_hash = keep_hash  # pretend the verifier came back
    endpoint_db_session.commit()
    for call in (lambda: agent_http.post("/api/endpoints/heartbeat", headers=old),
                 lambda: ingest(agent_http, old),
                 lambda: agent_http.post(REGISTER, json={"display_name": "x"}, headers=old)):
        assert call().status_code == 401


# ---------------------------------------------------------------- operator CLI paths (service level)


def test_operator_revoke_is_final_and_reinstate_is_the_explicit_recovery_for_legacy_endpoints(agent_http, shared_key, endpoint_db_session):
    legacy = agent_http.post(REGISTER, json={"endpoint_id": UUID_A, "display_name": "LEGACY"}, headers=shared_key).json()
    old = _headers(legacy)
    assert agent_http.post("/api/endpoints/heartbeat", headers=old).status_code == 200

    assert endpoint_identity_service.revoke_credential(endpoint_db_session, UUID_A) is True
    assert agent_http.post("/api/endpoints/heartbeat", headers=old).status_code == 401
    assert agent_http.post(REGISTER, json={"endpoint_id": UUID_A}, headers=shared_key).status_code == 403  # final

    assert endpoint_identity_service.reinstate_endpoint(endpoint_db_session, UUID_A) == "reinstated"
    renewed = agent_http.post(REGISTER, json={"endpoint_id": UUID_A, "display_name": "LEGACY"}, headers=shared_key)
    assert renewed.status_code == 200 and renewed.json()["agent_credential"] != legacy["agent_credential"]
    assert agent_http.post("/api/endpoints/heartbeat", headers=old).status_code == 401  # the old credential never comes back
    assert agent_http.post("/api/endpoints/heartbeat", headers=_headers(renewed.json())).status_code == 200
    actions = [a.action for a in endpoint_db_session.query(AuditEvent).order_by(AuditEvent.id)]
    assert actions == ["endpoint.credential_revoked", "enrollment.legacy_reenroll_blocked", "endpoint.reinstated"]


def test_reinstate_refuses_request_linked_unrevoked_and_unknown_endpoints(client, alice, installer, agent_http, shared_key, endpoint_db_session):
    rid, data = enrolled_by_request(client, alice, agent_http)
    assert endpoint_identity_service.reinstate_endpoint(endpoint_db_session, UUID_A) == "request_linked"  # needs a new request
    revoke_request(client, rid)
    assert endpoint_identity_service.reinstate_endpoint(endpoint_db_session, UUID_A) == "request_linked"
    assert agent_http.post(REGISTER, json={"endpoint_id": UUID_A}, headers=shared_key).status_code == 403
    legacy = agent_http.post(REGISTER, json={"endpoint_id": UUID_B}, headers=shared_key)
    assert legacy.status_code == 200
    assert endpoint_identity_service.reinstate_endpoint(endpoint_db_session, UUID_B) == "not_revoked"
    assert endpoint_identity_service.reinstate_endpoint(endpoint_db_session, "no-such-endpoint") == "unknown"
    assert endpoint_identity_service.revoke_credential(endpoint_db_session, "no-such-endpoint") is False


def test_the_operator_cli_revokes_and_reinstates_against_a_throwaway_database(tmp_path):
    """Runs the controlled migration and operator CLI against a disposable database."""
    db = tmp_path / "cli.db"
    env = {**os.environ, "DATABASE_URL": f"sqlite:///{db.as_posix()}"}
    root = Path(__file__).resolve().parents[2]
    script = str(root / "backend" / "manage_endpoints.py")

    def cli(*args):
        return subprocess.run([sys.executable, script, *args], capture_output=True, text=True, env=env, cwd=tmp_path, timeout=60)

    migration = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(root / "alembic.ini"), "upgrade", "head"],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
        timeout=60,
    )
    assert migration.returncode == 0, migration.stderr
    assert cli("--list").returncode == 0
    con = sqlite3.connect(db)
    con.execute("INSERT INTO endpoints (endpoint_id, status, registered_at, credential_hash) VALUES ('legacy-1','active','2026-01-01 00:00:00','sha256:abc')")
    con.execute("INSERT INTO endpoints (endpoint_id, status, registered_at, credential_hash, enrolled_request_id) VALUES ('portal-1','active','2026-01-01 00:00:00','sha256:def','req-1')")
    con.commit()
    status = lambda i: con.execute("SELECT status, credential_hash FROM endpoints WHERE endpoint_id=?", (i,)).fetchone()  # noqa: E731

    assert cli("--revoke-credential", "legacy-1").returncode == 0 and status("legacy-1") == ("revoked", None)
    assert cli("--revoke-credential", "portal-1").returncode == 0 and status("portal-1") == ("revoked", None)
    assert cli("--revoke-credential", "missing").returncode == 1
    assert cli("--reinstate", "legacy-1").returncode == 0 and status("legacy-1")[0] == "registered"
    refused = cli("--reinstate", "portal-1")
    assert refused.returncode == 1 and "new request" in refused.stderr and status("portal-1")[0] == "revoked"
    assert cli("--reinstate", "legacy-1").returncode == 1  # no longer revoked
    con.close()


# ---------------------------------------------------------------- compatibility and the production switch


def test_new_endpoints_and_already_enrolled_legacy_endpoints_are_unaffected(agent_http, shared_key):
    first = agent_http.post(REGISTER, json={"display_name": "NEW"}, headers=shared_key)
    assert first.status_code == 200
    h = _headers(first.json())
    assert agent_http.post(REGISTER, json={"display_name": "NEW2"}, headers=h).status_code == 200  # credentialed refresh
    assert agent_http.post("/api/endpoints/heartbeat", headers=h).status_code == 200
    assert ingest(agent_http, h).status_code == 200
    dup = agent_http.post(REGISTER, json={"endpoint_id": first.json()["endpoint_id"]}, headers=shared_key)
    assert dup.status_code == 409  # an enrolled endpoint is still refused with the original message


def test_legacy_enrollment_can_be_switched_off_without_affecting_enrolled_agents(client, alice, installer, agent_http, shared_key, monkeypatch):
    rid, data = enrolled_by_request(client, alice, agent_http)
    h = _headers(data)
    monkeypatch.setattr(settings, "legacy_enrollment_enabled", False)
    for headers in (shared_key, {"X-Agent-Api-Key": "wrong-key"}, {}):  # same answer whatever is presented
        r = agent_http.post(REGISTER, json={"display_name": "NEW"}, headers=headers)
        assert r.status_code == 403 and "disabled" in r.json()["detail"]
    assert agent_http.post(REGISTER, json={"display_name": "refresh"}, headers=h).status_code == 200  # credentialed refresh
    assert agent_http.post("/api/endpoints/heartbeat", headers=h).status_code == 200
    assert ingest(agent_http, h).status_code == 200
    assert _redeem(agent_http, _mint_new_request_code(client, alice), endpoint_id=UUID_B).status_code == 200  # portal enrollment unaffected


def test_legacy_enrollment_defaults_off_in_production_on_elsewhere_and_is_overridable(monkeypatch):
    monkeypatch.setattr(settings, "legacy_enrollment_enabled", None)
    monkeypatch.setattr(settings, "environment", "local")
    assert settings.legacy_enrollment_allowed is True  # existing deployments behave exactly as before
    monkeypatch.setattr(settings, "environment", "production")
    assert settings.legacy_enrollment_allowed is False
    monkeypatch.setattr(settings, "legacy_enrollment_enabled", True)
    assert settings.legacy_enrollment_allowed is True
    monkeypatch.setattr(settings, "environment", "local")
    monkeypatch.setattr(settings, "legacy_enrollment_enabled", False)
    assert settings.legacy_enrollment_allowed is False
