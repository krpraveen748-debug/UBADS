"""
Tests for agent/checkpoint.py's persistent collection cursor. Every test
redirects STATE_DIR/CHECKPOINT_FILE to a pytest agent_tmp_dir — never
touches the real agent/.state/checkpoint.json.
"""

import checkpoint as checkpoint_module


def _isolate(agent_tmp_dir, monkeypatch):
    monkeypatch.setattr(checkpoint_module, "STATE_DIR", agent_tmp_dir)
    monkeypatch.setattr(checkpoint_module, "CHECKPOINT_FILE", agent_tmp_dir / "checkpoint.json")


def test_first_collection_has_no_cursor(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    assert checkpoint_module.get_cursor("Security", "authentication") is None


def test_commit_persists_cursor_for_subsequent_collection(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    checkpoint_module.commit("Security", {"authentication": 100})
    assert checkpoint_module.get_cursor("Security", "authentication") == 100


def test_cursor_only_moves_forward(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    checkpoint_module.commit("Security", {"authentication": 100})
    checkpoint_module.commit("Security", {"authentication": 50})  # stale/out-of-order commit
    assert checkpoint_module.get_cursor("Security", "authentication") == 100


def test_categories_and_channels_are_independent(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    checkpoint_module.commit("Security", {"authentication": 10, "file_activity": 20})
    checkpoint_module.commit("Application", {"authentication": 999})
    assert checkpoint_module.get_cursor("Security", "authentication") == 10
    assert checkpoint_module.get_cursor("Security", "file_activity") == 20
    assert checkpoint_module.get_cursor("Application", "authentication") == 999


def test_checkpoint_survives_reload_restart_simulation(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    checkpoint_module.commit("Security", {"authentication": 42})
    # Simulate a fresh process: nothing in memory, only load_checkpoint()
    # reading the file back from disk.
    reloaded = checkpoint_module.load_checkpoint()
    assert reloaded["Security::authentication"] == 42


def test_corrupt_checkpoint_file_recovers_to_empty(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    checkpoint_module.STATE_DIR.mkdir(parents=True, exist_ok=True)
    checkpoint_module.CHECKPOINT_FILE.write_text("{not valid json", encoding="utf-8")
    assert checkpoint_module.load_checkpoint() == {}
    assert checkpoint_module.get_cursor("Security", "authentication") is None


def test_checkpoint_file_holding_a_json_array_recovers_to_empty(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    checkpoint_module.STATE_DIR.mkdir(parents=True, exist_ok=True)
    checkpoint_module.CHECKPOINT_FILE.write_text("[1, 2, 3]", encoding="utf-8")
    assert checkpoint_module.load_checkpoint() == {}


def test_rollover_detected_and_cursor_reset(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    checkpoint_module.commit("Security", {"authentication": 5000})
    rolled_over = checkpoint_module.check_for_rollover("Security", "authentication", current_newest_record_id=10)
    assert rolled_over is True
    assert checkpoint_module.get_cursor("Security", "authentication") is None


def test_no_rollover_when_newest_record_id_still_ahead(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    checkpoint_module.commit("Security", {"authentication": 100})
    rolled_over = checkpoint_module.check_for_rollover("Security", "authentication", current_newest_record_id=500)
    assert rolled_over is False
    assert checkpoint_module.get_cursor("Security", "authentication") == 100


def test_rollover_check_is_a_noop_when_channel_currently_empty(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    checkpoint_module.commit("Security", {"authentication": 100})
    rolled_over = checkpoint_module.check_for_rollover("Security", "authentication", current_newest_record_id=None)
    assert rolled_over is False
    assert checkpoint_module.get_cursor("Security", "authentication") == 100
