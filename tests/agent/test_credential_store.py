"""
Tests for agent/credential_store.py. Every test redirects
STATE_DIR/CREDENTIAL_FILE to a pytest agent_tmp_dir — never touches the
real agent/.state/credentials.json.
"""

from types import SimpleNamespace

import pytest

import agent as agent_module
import credential_store as credential_store_module
from config import settings


def _isolate(agent_tmp_dir, monkeypatch):
    monkeypatch.setattr(credential_store_module, "STATE_DIR", agent_tmp_dir)
    monkeypatch.setattr(credential_store_module, "CREDENTIAL_FILE", agent_tmp_dir / "credentials.json")


def test_no_credential_file_means_not_enrolled(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    assert credential_store_module.load_credential() is None


def test_save_and_load_round_trip(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    credential_store_module.save_credential(endpoint_id="e1", agent_credential="secret-value")
    loaded = credential_store_module.load_credential()
    assert loaded.endpoint_id == "e1"
    assert loaded.agent_credential == "secret-value"


def test_corrupt_credential_file_treated_as_not_enrolled(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    credential_store_module.STATE_DIR.mkdir(parents=True, exist_ok=True)
    credential_store_module.CREDENTIAL_FILE.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(credential_store_module.CredentialCorruptError):
        credential_store_module.load_credential()
    assert credential_store_module.CREDENTIAL_FILE.read_text(encoding="utf-8") == "{not valid json"


def test_missing_credential_is_distinct_from_corrupt_credential(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    assert credential_store_module.load_credential() is None

    credential_store_module.CREDENTIAL_FILE.write_text("{", encoding="utf-8")
    with pytest.raises(credential_store_module.CredentialCorruptError):
        credential_store_module.load_credential()


def test_unsupported_credential_format_is_corrupt_and_preserved(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    original = '{"protection":"unknown","agent_credential":"synthetic"}'
    credential_store_module.CREDENTIAL_FILE.write_text(original, encoding="utf-8")

    with pytest.raises(credential_store_module.CredentialCorruptError):
        credential_store_module.load_credential()

    assert credential_store_module.CREDENTIAL_FILE.read_text(encoding="utf-8") == original


def test_non_utf8_credential_is_corrupt_and_preserved(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    original = b"\xff\xfe\xfa"
    credential_store_module.CREDENTIAL_FILE.write_bytes(original)

    with pytest.raises(credential_store_module.CredentialCorruptError):
        credential_store_module.load_credential()

    assert credential_store_module.CREDENTIAL_FILE.read_bytes() == original


def test_inaccessible_credential_is_not_treated_as_missing(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    real_read_text = credential_store_module.CREDENTIAL_FILE.__class__.read_text

    def deny_credential_read(path, *args, **kwargs):
        if path == credential_store_module.CREDENTIAL_FILE:
            raise PermissionError("synthetic access denial")
        return real_read_text(path, *args, **kwargs)

    monkeypatch.setattr(credential_store_module.CREDENTIAL_FILE.__class__, "read_text", deny_credential_read)
    with pytest.raises(credential_store_module.CredentialInaccessibleError):
        credential_store_module.load_credential()


def test_saving_never_overwrites_an_existing_valid_credential(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    credential_store_module.save_credential("e1", "original-secret")
    original = credential_store_module.CREDENTIAL_FILE.read_bytes()

    with pytest.raises(credential_store_module.CredentialAlreadyExistsError):
        credential_store_module.save_credential("e2", "replacement-secret")

    assert credential_store_module.CREDENTIAL_FILE.read_bytes() == original
    assert credential_store_module.load_credential().endpoint_id == "e1"


def test_corrupt_credential_does_not_trigger_automatic_enrollment(
    agent_tmp_dir, monkeypatch
):
    _isolate(agent_tmp_dir, monkeypatch)
    credential_store_module.CREDENTIAL_FILE.write_text("{", encoding="utf-8")
    original = credential_store_module.CREDENTIAL_FILE.read_bytes()
    monkeypatch.setattr(settings, "agent_api_key", "synthetic-enrollment-key")

    class Client:
        called = False

        def enroll_endpoint(self, **_kwargs):
            self.called = True
            raise AssertionError("corrupt credentials must not trigger enrollment")

    client = Client()
    with pytest.raises(credential_store_module.CredentialCorruptError):
        agent_module._ensure_enrolled(
            client,
            SimpleNamespace(
                endpoint_id="synthetic-endpoint",
                display_name="synthetic",
                operating_system="synthetic",
                agent_version="synthetic",
            ),
        )

    assert not client.called
    assert credential_store_module.CREDENTIAL_FILE.read_bytes() == original


def test_clear_credential_removes_file(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    credential_store_module.save_credential(endpoint_id="e1", agent_credential="secret-value")
    credential_store_module.clear_credential()
    assert credential_store_module.load_credential() is None


def test_credential_value_never_appears_in_repr_by_accident(agent_tmp_dir, monkeypatch):
    # Not a security guarantee by itself, but documents the dataclass has
    # no custom repr suppression needed today because nothing logs it.
    _isolate(agent_tmp_dir, monkeypatch)
    credential_store_module.save_credential(endpoint_id="e1", agent_credential="secret-value")
    on_disk = credential_store_module.CREDENTIAL_FILE.read_text(encoding="utf-8")
    # Phase 16: protected with Windows DPAPI - never plain text on disk.
    assert "secret-value" not in on_disk
    assert "secret-value" not in repr(credential_store_module.load_credential())
