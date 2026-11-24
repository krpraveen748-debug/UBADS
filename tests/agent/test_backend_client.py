"""
Tests for agent/backend_client.py. Every HTTP call is mocked via
monkeypatching `requests.request` — no test ever makes a real network
call or requires real credentials.
"""

import requests

import backend_client as backend_client_module
from backend_client import BackendClient
from config import settings


class _FakeResponse:
    def __init__(self, status_code, json_data=None, text=""):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text

    def json(self):
        if self._json_data is None:
            raise ValueError("no json body")
        return self._json_data


def test_successful_request_returns_ok(monkeypatch):
    monkeypatch.setattr(requests, "request", lambda *a, **kw: _FakeResponse(200, {"status": "ok"}))
    result = BackendClient().check_health()
    assert result.ok is True
    assert result.data == {"status": "ok"}


def test_enroll_sends_only_enrollment_key(monkeypatch):
    captured = {}

    def fake_request(method, url, json=None, headers=None, timeout=None):
        captured["headers"] = headers
        return _FakeResponse(200, {"endpoint_id": "e1", "agent_credential": "secret-cred"})

    monkeypatch.setattr(requests, "request", fake_request)
    monkeypatch.setattr(settings, "agent_api_key", "enrollment-key-value")

    client = BackendClient()
    result = client.enroll_endpoint(endpoint_id="e1", display_name="d", operating_system="os", agent_version="v")
    assert captured["headers"]["X-Agent-Api-Key"] == "enrollment-key-value"
    assert "X-Endpoint-Id" not in captured["headers"]
    assert "X-Agent-Credential" not in captured["headers"]
    assert result.data["agent_credential"] == "secret-cred"


def test_register_heartbeat_ingest_send_only_per_agent_credential(monkeypatch):
    captured = []

    def fake_request(method, url, json=None, headers=None, timeout=None):
        captured.append(dict(headers))
        return _FakeResponse(200, {})

    monkeypatch.setattr(requests, "request", fake_request)
    monkeypatch.setattr(settings, "agent_api_key", "enrollment-key-value")

    client = BackendClient()
    client.register(
        endpoint_id="e1", agent_credential="cred-1", display_name="d", operating_system="os", agent_version="v"
    )
    client.heartbeat(endpoint_id="e1", agent_credential="cred-1")
    client.ingest_events(endpoint_id="e1", agent_credential="cred-1", log_name="Security", events=[])

    for headers in captured:
        assert headers["X-Endpoint-Id"] == "e1"
        assert headers["X-Agent-Credential"] == "cred-1"
        assert "X-Agent-Api-Key" not in headers


def test_connection_error_retries_bounded_times(monkeypatch):
    attempts = {"count": 0}

    def fake_request(*a, **kw):
        attempts["count"] += 1
        raise requests.exceptions.ConnectionError("boom")

    monkeypatch.setattr(requests, "request", fake_request)
    monkeypatch.setattr(backend_client_module.time, "sleep", lambda _seconds: None)

    result = BackendClient().check_health()
    assert result.ok is False
    assert attempts["count"] == backend_client_module.MAX_ATTEMPTS


def test_timeout_is_reported_not_raised(monkeypatch):
    def fake_request(*a, **kw):
        raise requests.exceptions.Timeout("too slow")

    monkeypatch.setattr(requests, "request", fake_request)
    monkeypatch.setattr(backend_client_module.time, "sleep", lambda _seconds: None)

    result = BackendClient().check_health()
    assert result.ok is False
    assert "timed out" in result.error.lower()


def test_401_is_not_retried(monkeypatch):
    attempts = {"count": 0}

    def fake_request(*a, **kw):
        attempts["count"] += 1
        return _FakeResponse(401, {"detail": "Invalid or missing agent credential."})

    monkeypatch.setattr(requests, "request", fake_request)
    result = BackendClient().ingest_events(endpoint_id="e1", agent_credential="bad", log_name="Security", events=[])
    assert result.ok is False
    assert result.status_code == 401
    assert attempts["count"] == 1


def test_503_is_retried_then_reported(monkeypatch):
    attempts = {"count": 0}

    def fake_request(*a, **kw):
        attempts["count"] += 1
        return _FakeResponse(503, {"detail": "Agent authentication is not configured on this server."})

    monkeypatch.setattr(requests, "request", fake_request)
    monkeypatch.setattr(backend_client_module.time, "sleep", lambda _seconds: None)

    result = BackendClient().enroll_endpoint(endpoint_id="e1", display_name="d", operating_system="os", agent_version="v")
    assert result.ok is False
    assert result.status_code == 503
    assert attempts["count"] == backend_client_module.MAX_ATTEMPTS


def test_credential_value_never_appears_in_result(monkeypatch):
    monkeypatch.setattr(requests, "request", lambda *a, **kw: _FakeResponse(401, {"detail": "unauthorized"}))

    result = BackendClient().ingest_events(
        endpoint_id="e1", agent_credential="TOTALLY-SECRET-VALUE", log_name="Security", events=[]
    )
    assert "TOTALLY-SECRET-VALUE" not in str(result)
