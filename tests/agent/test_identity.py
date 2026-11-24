"""
Tests for agent/identity.py. Every test redirects STATE_DIR/IDENTITY_FILE
to a pytest agent_tmp_dir — never touches the real agent/.state/identity.json.
"""

import pytest

import agent as agent_module
import identity as identity_module
import credential_store as credential_store_module
from config import settings


@pytest.fixture()
def isolated_state(agent_tmp_dir, monkeypatch):
    state_dir = agent_tmp_dir / "agent-state"
    identity_file = state_dir / "identity.json"
    monkeypatch.setattr(identity_module, "STATE_DIR", state_dir)
    monkeypatch.setattr(identity_module, "IDENTITY_FILE", identity_file)
    monkeypatch.setattr(settings, "endpoint_id", None)
    return identity_file


def test_generates_identity_on_first_run(isolated_state):
    identity = identity_module.load_or_create_identity()
    assert identity.endpoint_id
    assert isolated_state.exists()


def test_identity_persists_across_calls(isolated_state):
    first = identity_module.load_or_create_identity()
    second = identity_module.load_or_create_identity()
    assert first.endpoint_id == second.endpoint_id


def test_identity_only_exposes_safe_fields(isolated_state):
    identity = identity_module.load_or_create_identity()
    # No username, IP, MAC, or hardware serial fields exist at all.
    assert set(vars(identity).keys()) == {
        "endpoint_id",
        "display_name",
        "operating_system",
        "agent_version",
        "created_at",
    }


def test_explicit_endpoint_id_override_updates_persisted_file(isolated_state, monkeypatch):
    identity_module.load_or_create_identity()
    monkeypatch.setattr(settings, "endpoint_id", "explicit-id-123")
    updated = identity_module.load_or_create_identity()
    assert updated.endpoint_id == "explicit-id-123"


def test_missing_identity_with_existing_credential_does_not_create_new_id(agent_tmp_dir, monkeypatch):
    state_dir = agent_tmp_dir / "protected-state"
    identity_file = state_dir / "identity.json"
    credential_file = state_dir / "credentials.json"
    credential_file.parent.mkdir(parents=True)
    credential_file.write_text('{"endpoint_id":"existing"}', encoding="utf-8")
    monkeypatch.setattr(identity_module, "STATE_DIR", state_dir)
    monkeypatch.setattr(identity_module, "IDENTITY_FILE", identity_file)
    monkeypatch.setattr(credential_store_module, "CREDENTIAL_FILE", credential_file)
    monkeypatch.setattr(identity_module.paths, "is_frozen_production", lambda: True)
    monkeypatch.setattr(identity_module.paths, "get_legacy_state_dir", lambda: agent_tmp_dir / "legacy-state")

    with pytest.raises(identity_module.IdentityStateError):
        identity_module.load_or_create_identity()
    assert not identity_file.exists()


def test_corrupt_installed_identity_is_not_overwritten(agent_tmp_dir, monkeypatch):
    state_dir = agent_tmp_dir / "protected-state"
    identity_file = state_dir / "identity.json"
    identity_file.parent.mkdir(parents=True)
    identity_file.write_text("{", encoding="utf-8")
    monkeypatch.setattr(identity_module, "STATE_DIR", state_dir)
    monkeypatch.setattr(identity_module, "IDENTITY_FILE", identity_file)
    monkeypatch.setattr(identity_module.paths, "is_frozen_production", lambda: True)

    with pytest.raises(identity_module.IdentityStateError):
        identity_module.load_or_create_identity()
    assert identity_file.read_text(encoding="utf-8") == "{"


def test_identity_state_error_is_reported_without_traceback(monkeypatch, capsys):
    def reject_existing_identity():
        raise identity_module.IdentityStateError("synthetic corrupt identity")

    monkeypatch.setattr(agent_module, "is_frozen_production", lambda: True)
    monkeypatch.setattr(agent_module, "ensure_protected_storage", lambda: None)
    monkeypatch.setattr(agent_module, "load_or_create_identity", reject_existing_identity)

    assert agent_module.main(["--identity"]) == 1
    output = capsys.readouterr()
    assert "No replacement endpoint identity was created" in output.err
    assert "Traceback" not in output.err
