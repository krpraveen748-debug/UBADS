import pytest

import protected_storage


def test_storage_layout_is_created_under_isolated_root(agent_tmp_dir, monkeypatch):
    monkeypatch.setattr(protected_storage, "_apply_acl", lambda path, directory: None)
    monkeypatch.setattr(protected_storage, "_verify_acl", lambda path, directory: True)
    root = agent_tmp_dir / "ProgramData" / "UBADS" / "Agent"

    config_dir, state_dir, log_dir = protected_storage.ensure_protected_storage(root)

    assert (config_dir, state_dir, log_dir) == (root / "config", root / "state", root / "logs")
    assert all(path.is_dir() for path in (root.parent, root, config_dir, state_dir, log_dir))


def test_acl_verification_failure_fails_closed(agent_tmp_dir, monkeypatch):
    monkeypatch.setattr(protected_storage, "_apply_acl", lambda path, directory: None)
    monkeypatch.setattr(protected_storage, "_verify_acl", lambda path, directory: False)

    with pytest.raises(protected_storage.ProtectedStorageError, match="ACL verification failed"):
        protected_storage.ensure_protected_storage(agent_tmp_dir / "Agent")


def test_existing_descendants_are_also_acl_verified(agent_tmp_dir, monkeypatch):
    root = agent_tmp_dir / "ProgramData" / "UBADS" / "Agent"
    existing = root / "state" / "identity.json"
    existing.parent.mkdir(parents=True)
    existing.write_text('{"endpoint_id":"isolated"}', encoding="utf-8")
    secured = []
    verified = []
    monkeypatch.setattr(protected_storage, "_apply_acl", lambda path, directory: secured.append((path, directory)))
    monkeypatch.setattr(
        protected_storage, "_verify_acl", lambda path, directory: verified.append((path, directory)) or True
    )

    protected_storage.ensure_protected_storage(root)

    assert (existing, False) in verified


def test_existing_data_with_invalid_acl_is_not_repaired(agent_tmp_dir, monkeypatch):
    root = agent_tmp_dir / "ProgramData" / "UBADS" / "Agent"
    existing = root / "state" / "identity.json"
    existing.parent.mkdir(parents=True)
    existing.write_text("existing endpoint state", encoding="utf-8")
    applied = []
    monkeypatch.setattr(protected_storage, "_apply_acl", lambda path, directory: applied.append(path))
    monkeypatch.setattr(protected_storage, "_verify_acl", lambda path, directory: False)

    with pytest.raises(protected_storage.ProtectedStorageError):
        protected_storage.ensure_protected_storage(root)
    assert applied == []
