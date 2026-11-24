"""
Tests for agent/state.py's bounded pending-events buffer. Every test
redirects STATE_DIR/PENDING_FILE to a pytest agent_tmp_dir.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

import agent as agent_module
import state as state_module


def _isolate(agent_tmp_dir, monkeypatch):
    pending_file = agent_tmp_dir / "pending_events.jsonl"
    monkeypatch.setattr(state_module, "STATE_DIR", agent_tmp_dir)
    monkeypatch.setattr(state_module, "PENDING_FILE", pending_file)


def test_append_and_load_pending(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    state_module.append_pending([{"event_id": 1}, {"event_id": 2}])
    assert state_module.load_pending() == [{"event_id": 1}, {"event_id": 2}]


def test_pending_buffer_is_capped_and_keeps_most_recent(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    monkeypatch.setattr(state_module, "MAX_PENDING_EVENTS", 3)

    events = [{"event_id": i} for i in range(10)]
    state_module.save_pending(events)

    loaded = state_module.load_pending()
    assert len(loaded) == 3
    assert loaded[-1]["event_id"] == 9  # most recent kept, oldest dropped


def test_clear_pending_removes_buffer(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    state_module.append_pending([{"event_id": 1}])
    state_module.clear_pending()
    assert state_module.load_pending() == []


def test_load_pending_on_missing_file_returns_empty_list(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    assert state_module.load_pending() == []


def test_corrupt_pending_buffer_is_preserved_and_reported(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    original = "{not valid json\n"
    state_module.PENDING_FILE.write_text(original, encoding="utf-8")

    with pytest.raises(state_module.PendingStateError):
        state_module.load_pending()

    assert state_module.PENDING_FILE.read_text(encoding="utf-8") == original


def test_pending_flush_failure_preserves_original_and_reload_after_restart(
    agent_tmp_dir, monkeypatch
):
    _isolate(agent_tmp_dir, monkeypatch)
    original_events = [{"event_id": "original"}]
    state_module.save_pending(original_events)
    original_bytes = state_module.PENDING_FILE.read_bytes()

    def fail_fsync(_fd):
        raise OSError("synthetic flush failure")

    monkeypatch.setattr(state_module.os, "fsync", fail_fsync)

    with pytest.raises(state_module.PendingStateError, match="original buffer was preserved"):
        state_module.save_pending([{"event_id": "replacement"}])

    assert state_module.PENDING_FILE.read_bytes() == original_bytes
    env = {
        key: os.environ[key]
        for key in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
        if key in os.environ
    }
    env["UBADS_STATE_DIR"] = str(agent_tmp_dir)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "agent")
    result = subprocess.run(
        [sys.executable, "-c", "import state; print(state.load_pending())"],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    assert result.stdout.strip() == "[{'event_id': 'original'}]"


def test_pending_write_failure_preserves_original_and_reload_after_restart(
    agent_tmp_dir, monkeypatch
):
    _isolate(agent_tmp_dir, monkeypatch)
    state_module.save_pending([{"event_id": "original"}])
    original_bytes = state_module.PENDING_FILE.read_bytes()
    real_fdopen = state_module.os.fdopen

    class PartialFailureStream:
        def __init__(self, fd, *args, **kwargs):
            self.stream = real_fdopen(fd, *args, **kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def write(self, text):
            self.stream.write(text[: max(1, len(text) // 2)])
            self.stream.flush()
            raise OSError("synthetic partial write failure")

        def flush(self):
            self.stream.flush()

        def fileno(self):
            return self.stream.fileno()

    monkeypatch.setattr(state_module.os, "fdopen", PartialFailureStream)
    with pytest.raises(state_module.PendingStateError, match="original buffer was preserved"):
        state_module.save_pending([{"event_id": "replacement"}])

    assert state_module.PENDING_FILE.read_bytes() == original_bytes
    env = {
        key: os.environ[key]
        for key in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
        if key in os.environ
    }
    env["UBADS_STATE_DIR"] = str(agent_tmp_dir)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "agent")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import state; print(state.load_pending())",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    assert result.stdout.strip() == "[{'event_id': 'original'}]"


def test_pending_replace_failure_preserves_original_and_cleans_temp(
    agent_tmp_dir, monkeypatch
):
    _isolate(agent_tmp_dir, monkeypatch)
    original_events = [{"event_id": "original"}]
    state_module.save_pending(original_events)
    original_bytes = state_module.PENDING_FILE.read_bytes()

    def fail_replace(_source, _destination):
        raise OSError("synthetic replacement failure")

    monkeypatch.setattr(state_module.os, "replace", fail_replace)

    with pytest.raises(state_module.PendingStateError, match="original buffer was preserved"):
        state_module.save_pending([{"event_id": "replacement"}])

    assert state_module.PENDING_FILE.read_bytes() == original_bytes
    assert not list(agent_tmp_dir.glob(".pending_events-*.tmp"))


def test_pending_file_is_replaced_atomically_and_temp_is_secured(
    agent_tmp_dir, monkeypatch
):
    _isolate(agent_tmp_dir, monkeypatch)
    state_module.save_pending([{"event_id": "original"}])
    secured_paths = []
    replace_calls = []
    real_secure = state_module.secure_storage_file
    real_replace = state_module.os.replace

    def record_secure(path):
        secured_paths.append((path, path.stat().st_size))
        real_secure(path)

    def record_replace(source, destination):
        replace_calls.append((Path(source), Path(destination)))
        real_replace(source, destination)

    monkeypatch.setattr(state_module, "secure_storage_file", record_secure)
    monkeypatch.setattr(state_module.os, "replace", record_replace)
    state_module.save_pending([{"event_id": "replacement"}])

    assert state_module.load_pending() == [{"event_id": "replacement"}]
    assert any(path.name.startswith(".pending_events-") and size == 0 for path, size in secured_paths)
    assert len(replace_calls) == 1
    assert replace_calls[0][0].parent == state_module.STATE_DIR
    assert replace_calls[0][1] == state_module.PENDING_FILE
    assert not list(agent_tmp_dir.glob(".pending_events-*.tmp"))


def test_pending_save_cleans_abandoned_temp_files(agent_tmp_dir, monkeypatch):
    _isolate(agent_tmp_dir, monkeypatch)
    abandoned = agent_tmp_dir / ".pending_events-abandoned.tmp"
    abandoned.write_text("incomplete synthetic buffer", encoding="utf-8")
    os.utime(abandoned, (0, 0))

    state_module.save_pending([{"event_id": "committed"}])

    assert state_module.load_pending() == [{"event_id": "committed"}]
    assert not abandoned.exists()


def test_cli_reports_pending_state_error_without_traceback(monkeypatch, capsys):
    def reject_pending_state(args):
        raise state_module.PendingStateError("synthetic corrupt buffer")

    monkeypatch.setattr(agent_module, "_dispatch", reject_pending_state)

    assert agent_module.main(["--status"]) == 1
    output = capsys.readouterr()
    assert "could not safely read or update local state" in output.err
    assert "Traceback" not in output.err
