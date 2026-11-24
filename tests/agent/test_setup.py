"""Phase 16 Stage 1: URL policy, connection errors, user config, --setup."""

import json

import pytest
import requests

import agent as agent_module
import credential_store
import identity as identity_module
import user_config
from backend_client import BackendClient, BackendResult
from connection import InvalidBackendUrl, describe_request_error, validate_backend_url


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://ubads.example.com", "https://ubads.example.com"),
        ("https://ubads.example.com/", "https://ubads.example.com"),
        ("  https://ubads.example.com:8443/api ", "https://ubads.example.com:8443"),
        ("http://127.0.0.1:8000", "http://127.0.0.1:8000"),
    ],
)
def test_valid_urls_are_normalised(url, expected):
    assert validate_backend_url(url) == expected


@pytest.mark.parametrize("url", ["", "ubads.example.com", "ftp://x.com", "https://", "https://u:p@x.com", "https://x.com:abc"])
def test_malformed_urls_rejected(url):
    with pytest.raises(InvalidBackendUrl):
        validate_backend_url(url)


def test_plain_http_to_remote_host_rejected_unless_opted_in():
    with pytest.raises(InvalidBackendUrl, match="unencrypted"):
        validate_backend_url("http://192.168.1.20:8000")
    assert validate_backend_url("http://192.168.1.20:8000", allow_insecure_http=True) == "http://192.168.1.20:8000"


def test_loopback_can_be_refused_for_remote_setup():
    with pytest.raises(InvalidBackendUrl, match="THIS computer"):
        validate_backend_url("https://localhost", allow_loopback=False)


def test_error_messages_distinguish_causes():
    url = "https://x.example"
    assert "certificate" in describe_request_error(requests.exceptions.SSLError("bad"), url)
    assert "timed out" in describe_request_error(requests.exceptions.Timeout(), url)
    assert "DNS" in describe_request_error(requests.exceptions.ConnectionError("getaddrinfo failed"), url)
    assert "refused" in describe_request_error(requests.exceptions.ConnectionError("[WinError 10061] refused"), url)


def test_client_refuses_to_send_over_plain_http_to_remote(monkeypatch):
    called = []
    monkeypatch.setattr(requests, "request", lambda *a, **kw: called.append(1))
    result = BackendClient("http://10.0.0.5:8000", allow_insecure_http=False).check_health()
    assert not result.ok and "https" in result.error
    assert called == []


def test_user_config_roundtrip_preserves_other_keys(agent_tmp_dir, monkeypatch):
    monkeypatch.setattr(user_config, "get_user_config_path", lambda: agent_tmp_dir / "agent.env")
    user_config.write_user_config({"BACKEND_URL": "https://a.example", "BATCH_SIZE": "10"})
    user_config.write_user_config({"backend_url": "https://b.example"})
    assert user_config.read_user_config() == {"BACKEND_URL": "https://b.example", "BATCH_SIZE": "10"}


def test_frozen_production_writes_only_trusted_json_settings(agent_tmp_dir, monkeypatch):
    path = agent_tmp_dir / "config" / "agent.json"
    monkeypatch.setattr(user_config.paths, "is_frozen_production", lambda: True)
    monkeypatch.setattr(user_config, "get_user_config_path", lambda: path)
    monkeypatch.setattr(user_config, "secure_storage_file", lambda file_path: None)
    monkeypatch.setattr("protected_storage.ensure_protected_storage", lambda: None)

    user_config.write_user_config(
        {
            "BACKEND_URL": "https://ubads.example.test",
            "CATEGORIES": "authentication",
            "ALLOW_INSECURE_HTTP": "false",
        }
    )

    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved == {
        "version": 1,
        "backend_url": "https://ubads.example.test",
        "categories": "authentication",
    }


@pytest.fixture()
def setup_env(agent_tmp_dir, monkeypatch):
    monkeypatch.setattr(user_config, "get_user_config_path", lambda: agent_tmp_dir / "agent.env")
    monkeypatch.setattr(credential_store, "STATE_DIR", agent_tmp_dir)
    monkeypatch.setattr(credential_store, "CREDENTIAL_FILE", agent_tmp_dir / "credentials.json")
    monkeypatch.setattr(identity_module, "STATE_DIR", agent_tmp_dir)
    monkeypatch.setattr(identity_module, "IDENTITY_FILE", agent_tmp_dir / "identity.json")
    return agent_tmp_dir


def _args(**kw):
    import argparse

    base = dict(backend_url="https://ubads.example.com", enrollment_key="k", allow_insecure_http=False, allow_local=False)
    base.update(kw)
    return argparse.Namespace(**base)


def test_setup_enrolls_and_saves_url_but_never_the_key(setup_env, monkeypatch):
    monkeypatch.setattr(BackendClient, "check_health", lambda self: BackendResult(ok=True, status_code=200))
    monkeypatch.setattr(
        BackendClient,
        "enroll_endpoint",
        lambda self, **kw: BackendResult(ok=True, data={"endpoint_id": kw["endpoint_id"], "agent_credential": "cred"}),
    )
    assert agent_module.cmd_setup(_args(enrollment_key="SECRET-KEY")) == 0
    saved = (setup_env / "agent.env").read_text()
    assert "BACKEND_URL=https://ubads.example.com" in saved
    assert "SECRET-KEY" not in saved
    assert credential_store.load_credential().agent_credential == "cred"


def test_setup_saves_nothing_when_server_unreachable(setup_env, monkeypatch, capsys):
    monkeypatch.setattr(BackendClient, "check_health", lambda self: BackendResult(ok=False, error="refused the connection"))
    assert agent_module.cmd_setup(_args()) == 1
    assert not (setup_env / "agent.env").exists()
    assert "refused" in capsys.readouterr().err


def test_setup_rejects_localhost_without_flag(setup_env):
    assert agent_module.cmd_setup(_args(backend_url="http://127.0.0.1:8000")) == 2
    assert not (setup_env / "agent.env").exists()


def test_setup_wrong_enrollment_key_reports_clearly(setup_env, monkeypatch, capsys):
    monkeypatch.setattr(BackendClient, "check_health", lambda self: BackendResult(ok=True))
    monkeypatch.setattr(BackendClient, "enroll_endpoint", lambda self, **kw: BackendResult(ok=False, status_code=401, error="Invalid"))
    assert agent_module.cmd_setup(_args()) == 1
    assert "enrollment" in capsys.readouterr().err
    assert credential_store.load_credential() is None
