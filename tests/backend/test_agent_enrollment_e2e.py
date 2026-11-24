"""Stage 4D end to end: the REAL agent enrollment code (agent/enrollment.py + backend_client.py)
talking to the REAL backend application (in-process), with an isolated database and an
isolated agent state folder. Nothing about the backend is mocked; only the network hop is
replaced by calling the FastAPI app directly. No real endpoint, credential or event is used."""

import re

import pytest
import requests

import credential_store
import enrollment
import identity as identity_module
import user_config
from app.core.config import settings
from backend_client import BackendClient
from tests.backend.test_endpoint_requests import _login_client, _register, _request_body


@pytest.fixture()
def agent_state(tmp_path, monkeypatch):
    state = tmp_path / "agent-state"
    state.mkdir()
    monkeypatch.setattr(credential_store, "STATE_DIR", state)
    monkeypatch.setattr(credential_store, "CREDENTIAL_FILE", state / "credentials.json")
    monkeypatch.setattr(identity_module, "STATE_DIR", state)
    monkeypatch.setattr(identity_module, "IDENTITY_FILE", state / "identity.json")
    monkeypatch.setattr(user_config, "get_user_config_path", lambda: state / "agent.env")
    return state


@pytest.fixture()
def wire(anon_client, monkeypatch):
    """Routes the agent's HTTP calls into the in-process backend (the network hop only)."""
    from fastapi.testclient import TestClient

    from app.main import app

    http = TestClient(app)

    def fake_request(method, url, json=None, headers=None, timeout=None):
        path = "/" + url.split("://", 1)[1].split("/", 1)[1]
        r = http.request(method, path, json=json, headers=headers)

        class Resp:
            status_code = r.status_code
            text = r.text

            def json(self_inner):
                return r.json()

        return Resp()

    monkeypatch.setattr(requests, "request", fake_request)
    return http


@pytest.fixture()
def installer(tmp_path, monkeypatch):
    path = tmp_path / "UBADS-Agent-Setup.exe"
    path.write_bytes(b"MZ-stub")
    monkeypatch.setattr(settings, "installer_path", str(path))


def _code_for(client, scope=("authentication", "process_activity"), approve=("authentication",)):
    _register(client, "alice")
    alice = _login_client("alice")
    rid = alice.post("/api/endpoint-requests", json=_request_body(requested_scope=list(scope))).json()["id"]
    assert client.post(f"/api/admin/endpoint-requests/{rid}/approve", json={"approved_scope": list(approve)}).status_code == 200
    r = alice.post(f"/api/endpoint-requests/{rid}/enrollment-package")
    return rid, re.search(r'filename="UBADS-Agent-Setup--(.+)\.exe"', r.headers["content-disposition"]).group(1)


def _enroll(code):
    out, err = [], []
    secret = enrollment.SecretCode(code)
    rc = enrollment.run_enrollment(secret, allow_local=True, io=enrollment._Out(out=out.append, err=err.append))
    return rc, "\n".join(out + err)


def test_real_agent_enrolls_against_the_real_backend_and_then_works_normally(client, installer, agent_state, wire):
    rid, code = _code_for(client)
    rc, text = _enroll(code)
    assert rc == enrollment.EXIT_OK, text
    assert code not in text

    stored = credential_store.load_credential()
    assert stored and len(stored.agent_credential) >= 32
    assert user_config.read_user_config()["CATEGORIES"] == "authentication"  # the APPROVED (narrowed) scope, not the requested one
    assert "dpapi-user" in (agent_state / "credentials.json").read_text()

    # the existing agent client works with the freshly provisioned credential
    api = BackendClient("http://127.0.0.1:8000")
    cred = dict(endpoint_id=stored.endpoint_id, agent_credential=stored.agent_credential)
    assert api.register(display_name="E2E-PC", operating_system="Windows", agent_version="t", **cred).ok
    assert api.heartbeat(**cred).ok
    event = {"event_id": 4624, "event_type": "successful_logon", "event_category": "authentication", "timestamp": "2026-01-01T00:00:00.000000Z",
             "computer_name": "E2E-FIXTURE", "username": "fixture", "event_record_id": 1}
    other = dict(event, event_id=4688, event_type="process_creation", event_category="process_activity", event_record_id=2)
    result = api.ingest_events(log_name="Security", events=[event, other], **cred)
    assert result.ok and result.data["accepted"] == 1 and result.data["out_of_scope"] == 1  # only the approved category is stored

    # server side: request ENROLLED, endpoint bound to the request and scope
    detail = client.get(f"/api/admin/endpoint-requests/{rid}").json()
    assert detail["status"] == "ENROLLED" and detail["endpoint_id"] == stored.endpoint_id
    assert client.get("/api/endpoints").json()[0]["monitoring_scope"] == ["authentication"]


def test_replaying_the_same_code_and_enrolling_again_are_both_refused(client, installer, agent_state, wire):
    _, code = _code_for(client)
    assert _enroll(code)[0] == enrollment.EXIT_OK
    before = (agent_state / "credentials.json").read_bytes()
    assert _enroll(code)[0] == enrollment.EXIT_ALREADY_ENROLLED  # this machine is enrolled: the code is not even sent
    assert (agent_state / "credentials.json").read_bytes() == before

    (agent_state / "credentials.json").unlink()  # a different machine presents the same, already-used code
    (agent_state / "agent.env").unlink()
    (agent_state / "identity.json").unlink()
    rc, text = _enroll(code)
    assert rc == enrollment.EXIT_ALREADY_USED
    assert not (agent_state / "credentials.json").exists()


def test_revoked_authorization_is_reported_and_nothing_is_stored(client, installer, agent_state, wire):
    rid, code = _code_for(client)
    assert client.post(f"/api/admin/endpoint-requests/{rid}/revoke", json={"reason": "policy"}).status_code == 200
    rc, text = _enroll(code)
    assert rc == enrollment.EXIT_REVOKED
    assert not (agent_state / "credentials.json").exists() and not (agent_state / "agent.env").exists()


def test_revoking_after_enrollment_stops_the_agents_uploads(client, installer, agent_state, wire):
    rid, code = _code_for(client)
    assert _enroll(code)[0] == enrollment.EXIT_OK
    stored = credential_store.load_credential()
    api = BackendClient("http://127.0.0.1:8000")
    cred = dict(endpoint_id=stored.endpoint_id, agent_credential=stored.agent_credential)
    assert api.heartbeat(**cred).ok
    assert client.post(f"/api/admin/endpoint-requests/{rid}/revoke", json={"reason": "lost"}).status_code == 200
    assert not api.heartbeat(**cred).ok and api.heartbeat(**cred).status_code == 401
    assert not api.ingest_events(log_name="Security", events=[], **cred).ok


def test_garbage_code_is_rejected_by_the_real_backend(client, installer, agent_state, wire):
    from tests.agent.test_enrollment import make_code

    rc, text = _enroll(make_code("http://127.0.0.1:8000"))
    assert rc == enrollment.EXIT_INVALID_CODE
    assert not (agent_state / "credentials.json").exists()
