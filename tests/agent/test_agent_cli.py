"""
Tests for agent/agent.py's orchestration logic (_collect_one_cycle,
cmd_collect). Windows event collection and backend HTTP calls are mocked —
no real Windows Event Log access or network call is made. Event dicts
below are AGENT-TEST FIXTURES ONLY, not real collected data.
"""

import agent as agent_module
import checkpoint as checkpoint_module
import credential_store as credential_store_module
import runtime_state as runtime_state_module
import state as state_module
from config import settings


class _FakeResult:
    def __init__(self, ok, data=None, error=None, status_code=None):
        self.ok = ok
        self.data = data
        self.error = error
        self.status_code = status_code


def _valid_event(**overrides):
    base = {
        "event_id": 4624,
        "event_type": "successful_logon",
        "timestamp": "2026-01-01T00:00:00.000000Z",
        "computer_name": "TEST-FIXTURE-PC",
        "username": "test.fixture.user",
        "event_record_id": 100,
    }
    base.update(overrides)
    return base


def _isolate_agent_state(agent_tmp_dir, monkeypatch):
    monkeypatch.setattr(state_module, "STATE_DIR", agent_tmp_dir)
    monkeypatch.setattr(state_module, "PENDING_FILE", agent_tmp_dir / "pending.jsonl")
    monkeypatch.setattr(checkpoint_module, "STATE_DIR", agent_tmp_dir)
    monkeypatch.setattr(checkpoint_module, "CHECKPOINT_FILE", agent_tmp_dir / "checkpoint.json")
    monkeypatch.setattr(credential_store_module, "STATE_DIR", agent_tmp_dir)
    monkeypatch.setattr(credential_store_module, "CREDENTIAL_FILE", agent_tmp_dir / "credentials.json")
    monkeypatch.setattr(runtime_state_module, "STATE_DIR", agent_tmp_dir)
    monkeypatch.setattr(runtime_state_module, "RUNTIME_STATE_FILE", agent_tmp_dir / "runtime_state.json")


def test_collect_one_cycle_filters_invalid_events(monkeypatch):
    valid_event = _valid_event()
    invalid_event = {"event_id": None, "timestamp": None, "computer_name": None}

    def fake_collect_events(limit, event_ids, log_name, after_record_id=None, raise_errors=False):
        return [valid_event, invalid_event]

    monkeypatch.setattr(agent_module.collector, "collect_events", fake_collect_events)
    monkeypatch.setattr(agent_module.collector, "get_newest_record_id", lambda log_name: None)
    monkeypatch.setattr(settings, "categories", "authentication")

    result = agent_module._collect_one_cycle()
    assert result.events == [valid_event]
    assert result.cursor_candidates == {"authentication": 100}


def test_collect_one_cycle_skips_unknown_category(monkeypatch):
    monkeypatch.setattr(agent_module.collector, "get_newest_record_id", lambda log_name: None)
    monkeypatch.setattr(settings, "categories", "not_a_real_category")
    result = agent_module._collect_one_cycle()
    assert result.events == []
    assert result.category_status == {"not_a_real_category": "UNKNOWN_CATEGORY"}


def test_collect_one_cycle_handles_missing_pywin32_honestly(monkeypatch):
    def fake_collect_events(limit, event_ids, log_name, after_record_id=None, raise_errors=False):
        raise RuntimeError("pywin32 is required to read Windows Event Logs.")

    def fake_get_newest(log_name):
        raise RuntimeError("pywin32 is required to read Windows Event Logs.")

    monkeypatch.setattr(agent_module.collector, "collect_events", fake_collect_events)
    monkeypatch.setattr(agent_module.collector, "get_newest_record_id", fake_get_newest)
    monkeypatch.setattr(settings, "categories", "authentication")

    # Must not raise — the absence of pywin32 is a real, honestly-reported
    # limitation, not a crash.
    result = agent_module._collect_one_cycle()
    assert result.events == []
    assert result.category_status == {"authentication": agent_module.collector.STATUS_PYWIN32_MISSING}


def test_collect_one_cycle_reports_access_denied_honestly(monkeypatch):
    def fake_collect_events(limit, event_ids, log_name, after_record_id=None, raise_errors=False):
        assert raise_errors is True
        raise agent_module.collector.EventLogAccessDenied("access denied")

    monkeypatch.setattr(agent_module.collector, "collect_events", fake_collect_events)
    monkeypatch.setattr(agent_module.collector, "get_newest_record_id", lambda log_name: None)
    monkeypatch.setattr(settings, "categories", "authentication")

    result = agent_module._collect_one_cycle()
    assert result.events == []
    assert result.category_status == {"authentication": agent_module.collector.STATUS_ACCESS_DENIED}


def test_collect_one_cycle_uses_persisted_cursor(monkeypatch, agent_tmp_dir):
    _isolate_agent_state(agent_tmp_dir, monkeypatch)
    monkeypatch.setattr(settings, "categories", "authentication")
    checkpoint_module.commit("Security", {"authentication": 50})

    captured = {}

    def fake_collect_events(limit, event_ids, log_name, after_record_id=None, raise_errors=False):
        captured["after_record_id"] = after_record_id
        return []

    monkeypatch.setattr(agent_module.collector, "collect_events", fake_collect_events)
    monkeypatch.setattr(agent_module.collector, "get_newest_record_id", lambda log_name: 200)
    monkeypatch.setattr(settings, "log_channel", "Security")

    agent_module._collect_one_cycle()
    assert captured["after_record_id"] == 50


def _fake_identity():
    return type(
        "Identity",
        (),
        {"endpoint_id": "e1", "display_name": "d", "operating_system": "os", "agent_version": "v"},
    )()


def _seed_credential(agent_tmp_dir, monkeypatch):
    _isolate_agent_state(agent_tmp_dir, monkeypatch)
    credential_store_module.save_credential(endpoint_id="e1", agent_credential="cred-1")


def test_cmd_collect_buffers_when_backend_unreachable(monkeypatch, agent_tmp_dir):
    _seed_credential(agent_tmp_dir, monkeypatch)
    monkeypatch.setattr(
        agent_module, "_collect_one_cycle", lambda: agent_module.CollectionResult(events=[_valid_event()])
    )
    monkeypatch.setattr(agent_module, "load_or_create_identity", _fake_identity)

    class _FakeClient:
        def heartbeat(self, **kwargs):
            return _FakeResult(ok=True)

        def register(self, **kwargs):
            return _FakeResult(ok=True)

        def ingest_events(self, **kwargs):
            return _FakeResult(ok=False, error="backend unreachable")

    monkeypatch.setattr(agent_module, "BackendClient", lambda: _FakeClient())

    exit_code = agent_module.cmd_collect(None)
    assert exit_code == 1
    assert len(state_module.load_pending()) == 1


def test_cmd_collect_does_not_advance_checkpoint_on_failed_upload(monkeypatch, agent_tmp_dir):
    _seed_credential(agent_tmp_dir, monkeypatch)
    monkeypatch.setattr(settings, "log_channel", "Security")
    collection = agent_module.CollectionResult(
        events=[_valid_event(event_record_id=100)], cursor_candidates={"authentication": 100}
    )
    monkeypatch.setattr(agent_module, "_collect_one_cycle", lambda: collection)
    monkeypatch.setattr(agent_module, "load_or_create_identity", _fake_identity)

    class _FakeClient:
        def heartbeat(self, **kwargs):
            return _FakeResult(ok=True)

        def register(self, **kwargs):
            return _FakeResult(ok=True)

        def ingest_events(self, **kwargs):
            return _FakeResult(ok=False, error="backend unreachable")

    monkeypatch.setattr(agent_module, "BackendClient", lambda: _FakeClient())

    agent_module.cmd_collect(None)
    assert checkpoint_module.get_cursor("Security", "authentication") is None


def test_cmd_collect_clears_buffer_and_advances_checkpoint_on_success(monkeypatch, agent_tmp_dir):
    _seed_credential(agent_tmp_dir, monkeypatch)
    monkeypatch.setattr(settings, "log_channel", "Security")
    collection = agent_module.CollectionResult(
        events=[_valid_event(event_record_id=100)], cursor_candidates={"authentication": 100}
    )
    monkeypatch.setattr(agent_module, "_collect_one_cycle", lambda: collection)
    monkeypatch.setattr(agent_module, "load_or_create_identity", _fake_identity)

    class _FakeClient:
        def heartbeat(self, **kwargs):
            return _FakeResult(ok=True)

        def register(self, **kwargs):
            return _FakeResult(ok=True)

        def ingest_events(self, **kwargs):
            return _FakeResult(ok=True, data={"accepted": 1, "duplicates": 0, "validation_errors": 0, "errors": []})

    monkeypatch.setattr(agent_module, "BackendClient", lambda: _FakeClient())

    exit_code = agent_module.cmd_collect(None)
    assert exit_code == 0
    assert state_module.load_pending() == []
    assert checkpoint_module.get_cursor("Security", "authentication") == 100


def test_cmd_collect_does_not_reread_events_already_pending(monkeypatch, agent_tmp_dir):
    _seed_credential(agent_tmp_dir, monkeypatch)
    monkeypatch.setattr(settings, "log_channel", "Security")
    existing = _valid_event(event_record_id=100)
    state_module.append_pending([existing])

    collection = agent_module.CollectionResult(events=[existing], cursor_candidates={"authentication": 100})
    monkeypatch.setattr(agent_module, "_collect_one_cycle", lambda: collection)
    monkeypatch.setattr(agent_module, "load_or_create_identity", _fake_identity)

    captured = {}

    class _FakeClient:
        def heartbeat(self, **kwargs):
            return _FakeResult(ok=True)

        def register(self, **kwargs):
            return _FakeResult(ok=True)

        def ingest_events(self, **kwargs):
            captured["events"] = kwargs["events"]
            return _FakeResult(ok=True, data={"accepted": 1, "duplicates": 0, "validation_errors": 0, "errors": []})

    monkeypatch.setattr(agent_module, "BackendClient", lambda: _FakeClient())

    agent_module.cmd_collect(None)
    # The already-pending event is sent exactly once, not duplicated.
    assert captured["events"] == [existing]


def test_cmd_collect_enrolls_when_no_credential_stored(monkeypatch, agent_tmp_dir):
    _isolate_agent_state(agent_tmp_dir, monkeypatch)
    monkeypatch.setattr(settings, "agent_api_key", "enrollment-key")
    monkeypatch.setattr(settings, "log_channel", "Security")
    monkeypatch.setattr(
        agent_module, "_collect_one_cycle", lambda: agent_module.CollectionResult(events=[])
    )
    monkeypatch.setattr(agent_module, "load_or_create_identity", _fake_identity)

    calls = {"enroll": 0, "register": 0}

    class _FakeClient:
        def enroll_endpoint(self, **kwargs):
            calls["enroll"] += 1
            return _FakeResult(ok=True, data={"endpoint_id": "e1", "agent_credential": "issued-cred"})

        def heartbeat(self, **kwargs):

            return _FakeResult(ok=True)


        def register(self, **kwargs):
            calls["register"] += 1
            assert kwargs["agent_credential"] == "issued-cred"
            return _FakeResult(ok=True)

        def ingest_events(self, **kwargs):
            return _FakeResult(ok=True, data={"accepted": 0, "duplicates": 0, "validation_errors": 0, "errors": []})

    monkeypatch.setattr(agent_module, "BackendClient", lambda: _FakeClient())

    agent_module.cmd_collect(None)
    assert calls["enroll"] == 1
    stored = credential_store_module.load_credential()
    assert stored.agent_credential == "issued-cred"


def test_cmd_collect_never_calls_ingest_without_credential(monkeypatch, agent_tmp_dir):
    _isolate_agent_state(agent_tmp_dir, monkeypatch)
    monkeypatch.setattr(settings, "agent_api_key", None)
    monkeypatch.setattr(
        agent_module, "_collect_one_cycle", lambda: agent_module.CollectionResult(events=[_valid_event()])
    )
    monkeypatch.setattr(agent_module, "load_or_create_identity", _fake_identity)

    class _FakeClient:
        def ingest_events(self, **kwargs):
            raise AssertionError("ingest_events must never be called without a stored credential")

    monkeypatch.setattr(agent_module, "BackendClient", lambda: _FakeClient())

    exit_code = agent_module.cmd_collect(None)
    assert exit_code == 1
    assert len(state_module.load_pending()) == 1


def test_cli_requires_exactly_one_command():
    try:
        agent_module.main([])
    except SystemExit as exc:
        assert exc.code != 0
    else:
        raise AssertionError("expected argparse to exit when no command is given")
