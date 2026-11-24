"""Phase 16 Stage 3: DPAPI credential protection, single instance, stop flag,
Task Scheduler definition, resilient run loop. No test touches the real
agent state or the real Task Scheduler."""

import argparse
import json
import threading
import time

import pytest

import agent as agent_module
import credential_store
import process_control
import task_scheduler


@pytest.fixture()
def state(agent_tmp_dir, monkeypatch):
    monkeypatch.setattr(credential_store, "STATE_DIR", agent_tmp_dir)
    monkeypatch.setattr(credential_store, "CREDENTIAL_FILE", agent_tmp_dir / "credentials.json")
    monkeypatch.setattr(process_control, "STATE_DIR", agent_tmp_dir)
    return agent_tmp_dir


# --- credential protection -------------------------------------------------


def test_credential_is_not_plaintext_on_disk_and_round_trips(state):
    credential_store.save_credential("e1", "super-secret-value", "2026-01-01")
    raw = (state / "credentials.json").read_text()
    assert "super-secret-value" not in raw
    assert json.loads(raw)["protection"] == "dpapi-user"
    loaded = credential_store.load_credential()
    assert loaded.endpoint_id == "e1" and loaded.agent_credential == "super-secret-value"
    assert "super-secret-value" not in repr(loaded)


def test_legacy_plaintext_credential_is_loaded_then_upgraded(state):
    (state / "credentials.json").write_text(
        json.dumps({"endpoint_id": "e1", "agent_credential": "legacy-secret", "issued_at": None})
    )
    assert credential_store.load_credential().agent_credential == "legacy-secret"
    assert "legacy-secret" not in (state / "credentials.json").read_text()
    assert credential_store.load_credential().agent_credential == "legacy-secret"


def test_credential_that_cannot_be_decrypted_is_preserved_and_reported(state):
    credential_store.save_credential("e1", "secret")
    data = json.loads((state / "credentials.json").read_text())
    data["agent_credential_protected"] = "AAAA"  # as if protected for another user/PC
    (state / "credentials.json").write_text(json.dumps(data))
    corrupted = (state / "credentials.json").read_bytes()
    with pytest.raises(credential_store.CredentialCorruptError):
        credential_store.load_credential()
    assert (state / "credentials.json").read_bytes() == corrupted


def test_credential_persists_across_reload(state):
    credential_store.save_credential("e1", "persisted")
    # state lives on disk, not in module memory, so a fresh load (= a restart) sees it
    assert credential_store.load_credential().agent_credential == "persisted"


# --- single instance / stop ------------------------------------------------


def test_second_instance_is_refused_and_lock_frees_on_release(state):
    first = process_control.acquire_instance_lock()
    assert first is not None
    assert process_control.running_pid() is not None
    assert process_control.acquire_instance_lock() is None
    first.release()
    assert process_control.running_pid() is None
    again = process_control.acquire_instance_lock()
    assert again is not None
    again.release()


def test_stop_request_only_when_running_and_cleared_on_next_start(state):
    assert process_control.request_stop() is False
    assert not process_control.stop_requested()
    lock = process_control.acquire_instance_lock()
    assert process_control.request_stop() is True and process_control.stop_requested()
    lock.release()
    fresh = process_control.acquire_instance_lock()
    assert not process_control.stop_requested()  # stale flag cleared
    fresh.release()


def test_run_refuses_to_start_when_already_running(state, capsys):
    lock = process_control.acquire_instance_lock()
    try:
        assert agent_module._run_single_instance(argparse.Namespace()) == 3
        assert "already running" in capsys.readouterr().out
    finally:
        lock.release()


def test_collect_does_not_race_a_running_agent(state, monkeypatch):
    monkeypatch.setattr(agent_module, "cmd_collect", lambda a: pytest.fail("must not collect"))
    lock = process_control.acquire_instance_lock()
    try:
        assert agent_module.cmd_collect_guarded(argparse.Namespace()) == 0
    finally:
        lock.release()


# --- run loop --------------------------------------------------------------


def test_run_loop_survives_cycle_failure_and_stops_on_request(state, monkeypatch):
    calls = []

    def flaky(_args):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("network is down")
        return 0

    monkeypatch.setattr(agent_module, "cmd_collect", flaky)
    monkeypatch.setattr(agent_module.settings, "collection_interval", 1)
    lock = process_control.acquire_instance_lock()
    result = {}
    thread = threading.Thread(target=lambda: result.update(code=agent_module.cmd_run(argparse.Namespace())))
    thread.start()
    deadline = time.time() + 10
    while len(calls) < 2 and time.time() < deadline:
        time.sleep(0.1)
    assert process_control.request_stop()
    thread.join(10)
    lock.release()
    assert len(calls) >= 2, "loop must continue after a failed cycle"
    assert result["code"] == 0 and not thread.is_alive()


# --- Task Scheduler definition --------------------------------------------


def _xml(elevated):
    return task_scheduler.build_task_xml(
        user="PC\\alice", program="C:\\Program Files\\UBADS\\ubads-agent-bg.exe", arguments="--background",
        workdir="C:\\Program Files\\UBADS", elevated=elevated,
    )


def test_task_runs_as_installing_user_not_system_hidden_and_single_instance():
    xml = _xml(False)
    assert "<UserId>PC\\alice</UserId>" in xml and "SYSTEM" not in xml.upper().replace("SYSTEMS", "")
    assert "<LogonTrigger>" in xml and "<Hidden>true</Hidden>" in xml
    assert "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>" in xml
    assert "<RestartOnFailure>" in xml and "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>" in xml
    assert "<RunLevel>LeastPrivilege</RunLevel>" in xml
    assert "<RunLevel>HighestAvailable</RunLevel>" in _xml(True)


def test_task_xml_is_well_formed():
    import xml.dom.minidom

    xml.dom.minidom.parseString(_xml(True).split("?>", 1)[1])


def test_install_task_uses_schtasks_with_xml(monkeypatch, tmp_path):
    exe = tmp_path / "ubads-agent-bg.exe"
    exe.write_text("x")
    monkeypatch.setattr(task_scheduler, "background_command", lambda: (str(exe), "--background", str(tmp_path)))
    seen = {}

    def fake(*args):
        seen["args"] = args
        return task_scheduler.TaskResult(True, "ok")

    monkeypatch.setattr(task_scheduler, "_schtasks", fake)
    assert task_scheduler.install_task().ok
    assert seen["args"][:3] == ("/Create", "/TN", task_scheduler.TASK_NAME) and "/XML" in seen["args"]


def test_background_command_from_source_uses_windowless_python():
    program, arguments, _ = task_scheduler.background_command()
    assert program.lower().endswith(("pythonw.exe", "python.exe")) and "--background" in arguments


# --- Stage 4E: restart race with Task Scheduler (found in the real installer test) -------------


def test_start_waits_for_the_previous_task_run_to_finish_before_asking_the_scheduler(monkeypatch, state):
    """`--stop` returns when the agent's lock is free, but the task is still 'Running' for a moment and
    would silently ignore a new run. --start must wait for it to settle, then run the task."""
    states = iter(["Running", "Running", "Ready"])
    calls = []
    monkeypatch.setattr(agent_module.task_scheduler, "task_info", lambda: {"installed": True, "state": next(states, "Ready")})
    monkeypatch.setattr(agent_module.task_scheduler, "run_task", lambda: calls.append("run") or agent_module.task_scheduler.TaskResult(True, "ok"))
    monkeypatch.setattr(agent_module.time, "sleep", lambda s: None)
    started = {"n": 0}

    def fake_pid():
        started["n"] += 1
        return 4321 if "run" in calls else None  # appears only after the task was actually run

    monkeypatch.setattr(agent_module.process_control, "running_pid", fake_pid)
    assert agent_module.cmd_start(argparse.Namespace()) == 0
    assert calls == ["run"]  # exactly one run request, issued only once the scheduler was idle


def test_start_does_not_run_the_task_again_if_the_agent_came_up_while_waiting(monkeypatch, state):
    monkeypatch.setattr(agent_module.task_scheduler, "task_info", lambda: {"installed": True, "state": "Running"})
    monkeypatch.setattr(agent_module.task_scheduler, "run_task", lambda: pytest.fail("must not start a second instance"))
    monkeypatch.setattr(agent_module.time, "sleep", lambda s: None)
    pids = iter([None, 777])
    monkeypatch.setattr(agent_module.process_control, "running_pid", lambda: next(pids, 777))
    assert agent_module.cmd_start(argparse.Namespace()) == 0
