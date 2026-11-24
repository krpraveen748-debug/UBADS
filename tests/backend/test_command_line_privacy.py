"""Stage 4G / Finding 3, backend end to end: a command line (or any other non-allowlisted raw field)
sent by ANY client must not reach the database, any API response, or any log line.

Audit evidence this fixes: an event with CommandLine "... --password hunter2-SECRET" was stored in
raw_event_data verbatim. Assertions use assert_absent, which never prints the searched values."""

import json
import logging
import time

import pytest

from app.models.enrollment import AuditEvent, Notification
from app.repositories.pipeline_bridge import storage
from tests.backend.test_enrollment_tokens import (  # noqa: F401  (fixtures + helpers shared with the enrollment tests)
    UUID_A,
    _approved,
    _headers,
    _mint,
    _redeem,
    agent_http,
    alice,
    installer,
)
from tests.log_collector.test_event_sanitizer import COMMAND_LINES, SECRETS, assert_absent

REGISTER = "/api/endpoints/register"


def process_event(command_line, record_id=1, **over):
    e = {
        "event_id": 4688, "event_type": "process_creation", "event_category": "process_activity",
        "timestamp": "2026-03-05T09:00:00.000000Z", "computer_name": "PRIVACY-FIXTURE", "username": "fixture",
        "event_record_id": record_id, "process_name": "C:\\tools\\deploy.exe", "parent_process_name": "C:\\Windows\\explorer.exe",
        "raw_event_data": {
            "CommandLine": command_line, "NewProcessName": "C:\\tools\\deploy.exe", "SubjectUserName": "fixture",
            "ExtraSecretBlob": SECRETS["plain"], "Nested": {"CommandLine": command_line}, "ProcessId": ["0x1", command_line],
        },
    }
    e.update(over)
    return e


@pytest.fixture()
def scoped(client, alice, installer, agent_http):
    rid = _approved(client, alice, scope=("authentication", "process_activity"), approve_scope=("process_activity",))
    return _headers(_redeem(agent_http, _mint(alice, rid)[0], endpoint_id=UUID_A).json())


@pytest.fixture()
def legacy(agent_http, monkeypatch):
    from app.security import agent_auth

    monkeypatch.setattr(agent_auth.settings, "agent_api_key", "legacy-key")
    return _headers(agent_http.post(REGISTER, json={"display_name": "LEGACY"}, headers={"X-Agent-Api-Key": "legacy-key"}).json())


def ingest(agent_http, headers, *events):
    r = agent_http.post("/api/ingest/events", json={"log_name": "Security", "events": list(events)}, headers=headers)
    assert r.status_code == 200
    return r


@pytest.mark.parametrize("endpoint_kind", ["scoped", "legacy"])
def test_command_lines_do_not_reach_the_database_the_api_or_the_logs(request, client, agent_http, test_session, caplog, endpoint_kind):
    headers = request.getfixturevalue(endpoint_kind)
    with caplog.at_level(logging.DEBUG):
        response = ingest(agent_http, headers, *[process_event(c, record_id=i) for i, c in enumerate(COMMAND_LINES, start=1)])
        listing = client.get("/api/events", params={"limit": 100})
        details = [client.get(f"/api/events/{e['id']}") for e in listing.json()]
    body = response.json()
    assert body["accepted"] == len(COMMAND_LINES)

    rows = test_session.query(storage.EventRecord).all()
    assert len(rows) == len(COMMAND_LINES)
    stored = json.dumps([{c.name: str(getattr(r, c.name)) for c in r.__table__.columns} for r in rows])
    assert_absent(SECRETS, stored)  # every column of every stored row
    assert all("CommandLine" not in json.loads(r.raw_event_data) and "ExtraSecretBlob" not in json.loads(r.raw_event_data) for r in rows)
    assert all(json.loads(r.raw_event_data)["NewProcessName"] == "C:\\tools\\deploy.exe" for r in rows)  # useful facts retained

    assert_absent(SECRETS, response.text, listing.text, *[d.text for d in details])  # ingest response, list API, detail API
    assert_absent(SECRETS, caplog.text)  # application logs, including DEBUG
    assert listing.status_code == 200 and all(d.status_code == 200 for d in details)


def test_secrets_in_smuggled_free_text_columns_are_masked_too(client, scoped, agent_http, test_session):
    event = process_event(COMMAND_LINES[0], process_name=f'C:\\tools\\deploy.exe --password {SECRETS["password"]}',
                          file_path=None, failure_reason=None)
    ingest(agent_http, scoped, event)
    row = test_session.query(storage.EventRecord).one()
    assert_absent(SECRETS, row.process_name, client.get(f"/api/events/{row.id}").text)
    assert row.process_name.startswith("C:\\tools\\deploy.exe")


def test_rejected_events_do_not_echo_or_log_their_content(client, scoped, agent_http, test_session, caplog):
    bad = process_event(COMMAND_LINES[1])
    del bad["timestamp"]  # invalid -> rejected with a reason code
    unsupported = process_event(COMMAND_LINES[2], record_id=2, event_id=4672)  # unknown id -> rejected
    mismatch = process_event(COMMAND_LINES[3], record_id=3, event_category="authentication")  # forged label -> rejected
    with caplog.at_level(logging.DEBUG):
        response = ingest(agent_http, scoped, bad, unsupported, mismatch)
    assert response.json()["accepted"] == 0 and response.json()["validation_errors"] == 3
    assert_absent(SECRETS, response.text, caplog.text)
    assert test_session.query(storage.EventRecord).count() == 0


def test_notifications_and_audit_never_receive_event_content(client, scoped, agent_http, endpoint_db_session):
    ingest(agent_http, scoped, *[process_event(c, record_id=i) for i, c in enumerate(COMMAND_LINES, start=1)])
    everything = "".join(str(r) for r in endpoint_db_session.query(AuditEvent).all()) + "".join(
        f"{n.title}{n.message}" for n in endpoint_db_session.query(Notification).all())
    assert_absent(SECRETS, everything)


def test_hostile_oversized_values_are_handled_quickly_and_safely(scoped, agent_http, test_session):
    """A crafted value must neither crash ingestion nor make the scrubber burn CPU (regex backtracking)."""
    hostile = process_event("x", raw_event_data={
        "CommandLine": "a" * 200_000, "ObjectName": "a" * 200_000, "AccessList": ("token" + "a" * 40) * 5000,
        "NewProcessName": "--password " + " " * 100_000, "SubjectUserName": '"' * 100_000,
    }, process_name="Bearer " + "a" * 100_000)
    started = time.perf_counter()
    body = ingest(agent_http, scoped, hostile).json()
    assert body["accepted"] == 1
    assert time.perf_counter() - started < 5.0
    row = test_session.query(storage.EventRecord).one()
    assert max(len(v or "") for v in json.loads(row.raw_event_data).values()) <= 4096
    assert len(row.process_name) <= 4096


def test_existing_clients_keep_working_normal_events_are_unchanged(client, legacy, agent_http, test_session):
    """Compatibility: authentication/file/device events with ordinary raw fields round-trip untouched."""
    normal = {"event_id": 4624, "event_type": "successful_logon", "event_category": "authentication", "timestamp": "2026-03-05T09:00:00.000000Z",
              "computer_name": "PRIVACY-FIXTURE", "username": "bob", "event_record_id": 77, "logon_type": 2, "source_ip": "10.1.2.3",
              "raw_event_data": {"TargetUserName": "bob", "LogonType": "2", "IpAddress": "10.1.2.3", "AuthenticationPackageName": "Negotiate"}}
    ingest(agent_http, legacy, normal)
    row = test_session.query(storage.EventRecord).one()
    assert json.loads(row.raw_event_data) == normal["raw_event_data"]
    assert (row.username, row.source_ip, row.logon_type) == ("bob", "10.1.2.3", 2)
