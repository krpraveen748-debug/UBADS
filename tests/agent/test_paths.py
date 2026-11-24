"""
Tests for agent/paths.py — the frozen-aware state/config directory
resolution added in Phase 13 for the packaged executable. No test here
touches the real filesystem outside of computing paths (nothing is
created/written).
"""

from __future__ import annotations

import sys
from pathlib import Path

import paths as paths_module


def test_is_frozen_false_under_pytest():
    assert paths_module.is_frozen() is False


def test_get_state_dir_matches_source_layout_when_not_frozen():
    expected = Path(paths_module.__file__).resolve().parent / ".state"
    assert paths_module.get_state_dir() == expected


def test_get_config_dir_is_shared_config_folder_when_not_frozen():
    result = paths_module.get_config_dir()
    assert result.name == "config"
    # Same project-root-relative config/ every other component reads.
    assert (result / ".env.example").exists() or (result / ".env").exists() or result.exists()


def test_get_state_dir_uses_localappdata_when_frozen(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(paths_module, "get_program_data_dir", lambda: tmp_path)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "untrusted"))
    monkeypatch.setenv("UBADS_STATE_DIR", str(tmp_path / "untrusted" / "state"))
    try:
        result = paths_module.get_state_dir()
        assert result == tmp_path / "UBADS" / "Agent" / "state"
        assert paths_module.get_config_dir() == tmp_path / "UBADS" / "Agent" / "config"
        assert paths_module.get_log_dir() == tmp_path / "UBADS" / "Agent" / "logs"
        assert paths_module.get_user_config_path() == tmp_path / "UBADS" / "Agent" / "config" / "agent.json"
    finally:
        monkeypatch.delattr(sys, "frozen", raising=False)


def test_frozen_production_ignores_task_name_override(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(paths_module, "get_program_data_dir", lambda: tmp_path)
    monkeypatch.setenv("UBADS_TASK_NAME", "attacker-controlled-task")
    try:
        assert paths_module.get_task_name() == "UBADS Agent"
    finally:
        monkeypatch.delattr(sys, "frozen", raising=False)


def test_get_config_dir_uses_executable_directory_when_frozen(monkeypatch, tmp_path):
    fake_exe = tmp_path / "ubads-agent.exe"
    monkeypatch.setattr(paths_module, "_install_profile", lambda: {"mode": "test"})
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(fake_exe), raising=False)
    try:
        result = paths_module.get_config_dir()
        assert result == tmp_path
    finally:
        monkeypatch.delattr(sys, "frozen", raising=False)


def test_frozen_state_dir_never_equals_the_ephemeral_source_dir(monkeypatch, tmp_path):
    """The whole point of this module: a frozen run must NEVER resolve to
    a path computed from __file__ (which lives inside PyInstaller's
    temporary extraction directory and is deleted after each run)."""
    source_dir = Path(paths_module.__file__).resolve().parent / ".state"
    monkeypatch.setattr(paths_module, "get_program_data_dir", lambda: tmp_path)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    try:
        assert paths_module.get_state_dir() != source_dir
    finally:
        monkeypatch.delattr(sys, "frozen", raising=False)


def test_development_path_override_still_works(monkeypatch, tmp_path):
    override = tmp_path / "isolated-state"
    monkeypatch.setenv("UBADS_STATE_DIR", str(override))
    assert paths_module.get_state_dir() == override
