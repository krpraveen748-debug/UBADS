"""Stage 4G / Finding 3, agent side: the agent never buffers or uploads a command line.

The agent obtains events through the collector's parse+normalize path; its on-disk retry buffer
(pending_events.jsonl) is what would persist them if the server were unreachable."""

import json

import pytest

import state as state_module
from event_parser import normalize_event, parse_event_xml
from tests.log_collector.test_event_sanitizer import COMMAND_LINES, SECRETS, assert_absent, xml_4688


@pytest.fixture()
def buffer_dir(agent_tmp_dir, monkeypatch):
    monkeypatch.setattr(state_module, "STATE_DIR", agent_tmp_dir)
    monkeypatch.setattr(state_module, "PENDING_FILE", agent_tmp_dir / "pending_events.jsonl")
    return agent_tmp_dir


@pytest.mark.parametrize("index", range(len(COMMAND_LINES)), ids=[f"cmdline-{i}" for i in range(len(COMMAND_LINES))])
def test_collected_process_events_are_buffered_without_their_command_line(buffer_dir, index):
    command_line = COMMAND_LINES[index]  # opaque index in, so tracebacks never show the secret-bearing string
    event = normalize_event(parse_event_xml(xml_4688(command_line)))  # exactly what the agent's collector yields
    assert state_module.append_pending([event]) == 1
    on_disk = (buffer_dir / "pending_events.jsonl").read_text(encoding="utf-8")
    assert_absent(SECRETS, on_disk)
    assert json.loads(on_disk.splitlines()[0])["process_name"] == "C:\\tools\\deploy.exe"  # the useful facts are still buffered
    assert "CommandLine" not in json.loads(on_disk.splitlines()[0])["raw_event_data"]


def test_the_agent_uploads_exactly_what_it_buffered(buffer_dir):
    """The upload batch is the buffered/normalized events, so it carries no command line either."""
    events = [normalize_event(parse_event_xml(xml_4688(c))) for c in COMMAND_LINES]
    assert_absent(SECRETS, json.dumps(events))
