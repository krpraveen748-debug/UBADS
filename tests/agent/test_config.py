import json
import sys

import config as config_module
import agent as agent_module
import pytest
import protected_storage
from config import AgentSettings


def test_default_backend_url_is_local():
    s = AgentSettings()
    assert s.backend_url.startswith("http://127.0.0.1")


def test_no_secret_defaults(monkeypatch):
    # Never a hard-coded key/token — the safe *code* default is "unset".
    # log-collector/storage.py calls load_dotenv() at import time, which can
    # copy a locally configured AGENT_API_KEY into os.environ, so both the
    # env file and the process environment are bypassed here.
    monkeypatch.delenv("AGENT_API_KEY", raising=False)
    monkeypatch.delenv("ENDPOINT_ID", raising=False)
    s = AgentSettings(_env_file=None)
    assert s.agent_api_key is None
    assert s.endpoint_id is None


def test_category_list_parses_comma_separated_string():
    s = AgentSettings(categories="authentication, file_activity ,process_activity")
    assert s.category_list == ["authentication", "file_activity", "process_activity"]


def test_category_list_default_covers_all_four_categories():
    s = AgentSettings()
    assert set(s.category_list) == {
        "authentication",
        "file_activity",
        "process_activity",
        "device_activity",
    }


def _production_config(monkeypatch, tmp_path, contents):
    monkeypatch.setattr(config_module, "PRODUCTION_CONFIG_ERROR", None)
    monkeypatch.setattr(config_module, "PRODUCTION_CONFIG_MISSING", False)
    executable_dir = tmp_path / "Program Files" / "UBADS Agent"
    executable_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable_dir / "ubads-agent.exe"), raising=False)
    monkeypatch.setattr(config_module.paths, "get_program_data_dir", lambda: tmp_path / "ProgramData")
    monkeypatch.setattr(protected_storage, "verify_protected_storage", lambda: None)
    config_path = tmp_path / "ProgramData" / "UBADS" / "Agent" / "config" / "agent.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if contents is not None:
        config_path.write_text(json.dumps(contents), encoding="utf-8")
    return config_path


def test_frozen_production_ignores_environment_overrides(monkeypatch, tmp_path):
    config_path = _production_config(
        monkeypatch, tmp_path, {"version": 1, "backend_url": "https://ubads.example.test"}
    )
    monkeypatch.setenv("BACKEND_URL", "https://attacker.example.test")
    monkeypatch.setenv("ENDPOINT_ID", "attacker-endpoint")
    monkeypatch.setenv("AGENT_API_KEY", "synthetic-test-secret")
    monkeypatch.setenv("UBADS_STATE_DIR", str(tmp_path / "attacker-state"))
    monkeypatch.setenv("UBADS_TASK_NAME", "attacker-task")
    settings = config_module.load_settings()
    assert settings.backend_url == "https://ubads.example.test"
    assert settings.endpoint_id is None
    assert settings.agent_api_key is None
    assert config_path.exists()


@pytest.mark.parametrize("backend_url", ["http://ubads.example.test", "https://localhost"])
def test_frozen_production_rejects_non_https_or_loopback_backend(monkeypatch, tmp_path, backend_url):
    _production_config(monkeypatch, tmp_path, {"version": 1, "backend_url": backend_url})
    settings = config_module.load_settings()
    assert settings.backend_url == ""
    assert config_module.PRODUCTION_CONFIG_ERROR


def test_frozen_production_missing_configuration_fails_closed(monkeypatch, tmp_path):
    _production_config(monkeypatch, tmp_path, None)
    settings = config_module.load_settings()
    assert settings.backend_url == ""
    assert config_module.PRODUCTION_CONFIG_MISSING
    assert config_module.PRODUCTION_CONFIG_ERROR


def test_missing_installed_config_returns_clean_cli_error(monkeypatch, tmp_path, capsys):
    _production_config(monkeypatch, tmp_path, None)
    config_module.load_settings()
    monkeypatch.setattr(agent_module, "is_frozen_production", lambda: True)
    monkeypatch.setattr(agent_module, "ensure_protected_storage", lambda: None)

    assert agent_module.main(["--status"]) == 1
    assert "protected agent configuration is missing" in capsys.readouterr().err


def test_invalid_config_does_not_block_task_uninstall(monkeypatch, tmp_path):
    path = _production_config(monkeypatch, tmp_path, None)
    path.write_text("{", encoding="utf-8")
    config_module.load_settings()
    monkeypatch.setattr(agent_module, "is_frozen_production", lambda: True)
    monkeypatch.setattr(agent_module, "ensure_protected_storage", lambda: None)
    monkeypatch.setattr(agent_module, "cmd_stop", lambda args: 0)
    monkeypatch.setattr(
        agent_module.task_scheduler,
        "uninstall_task",
        lambda: agent_module.task_scheduler.TaskResult(True, ""),
    )

    assert agent_module.main(["--uninstall-task"]) == 0


def test_frozen_production_corrupt_configuration_fails_closed(monkeypatch, tmp_path):
    path = _production_config(monkeypatch, tmp_path, None)
    path.write_text("{", encoding="utf-8")
    settings = config_module.load_settings()
    assert settings.backend_url == ""
    assert not config_module.PRODUCTION_CONFIG_MISSING
    assert config_module.PRODUCTION_CONFIG_ERROR


def test_frozen_production_does_not_read_config_before_acl_verification(monkeypatch, tmp_path):
    path = _production_config(
        monkeypatch, tmp_path, {"version": 1, "backend_url": "https://ubads.example.test"}
    )

    def reject_unverified_storage():
        raise protected_storage.ProtectedStorageError("synthetic ACL failure")

    monkeypatch.setattr(protected_storage, "verify_protected_storage", reject_unverified_storage)

    settings = config_module.load_settings()

    assert settings.backend_url == ""
    assert config_module.PRODUCTION_CONFIG_ERROR
    assert path.exists()


def test_development_environment_overrides_remain_available(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.setenv("BACKEND_URL", "https://dev.example.test")
    assert config_module.load_settings().backend_url == "https://dev.example.test"
