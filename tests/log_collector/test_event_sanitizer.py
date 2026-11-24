"""Stage 4G / Finding 3: command lines and other secret-bearing fields never survive collection.

All "secrets" below are fabricated, realistic-looking values used only to prove they do not appear
anywhere. Assertions go through `assert_absent`, which NEVER prints the value it searched for, so a
failing run cannot leak them into test output either."""

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import event_sanitizer
from event_parser import normalize_event, parse_event_xml
from storage import Base, EventRecord, event_record_to_dict, insert_event

SECRETS = {
    "password": "P@ssw0rd!SuperSecret123",
    "github": "ghp_AbCdEf1234567890abcdef1234567890ABCD",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    "aws_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "aws_key_id": "AKIAIOSFODNN7EXAMPLE",
    "plain": "hunter2-SECRET-VALUE",
    "slack": "xoxb-123456789012-abcdefghijkl",
    "api": "sk-abcdefghijklmnopqrstuvwxyz0123",
}

COMMAND_LINES = [
    f'"C:\\tools\\deploy.exe" --password {SECRETS["password"]} --token {SECRETS["github"]}',
    f'curl.exe -H "Authorization: Bearer {SECRETS["jwt"]}" https://api.example.com/v1/items',
    f'cmd.exe /c set AWS_SECRET_ACCESS_KEY={SECRETS["aws_secret"]} && set AWS_ACCESS_KEY_ID={SECRETS["aws_key_id"]}',
    f'net.exe use \\\\srv\\share /user:corp\\bob {SECRETS["password"]}',
    f'mysql.exe -uroot -p{SECRETS["plain"]} -h db.internal',
    f'powershell.exe -NoP -c "$env:API=\'{SECRETS["api"]}\'; Invoke-RestMethod -Headers @{{token=\'{SECRETS["slack"]}\'}} https://x"',
]


def assert_absent(needles, *texts):
    """Fails WITHOUT echoing any needle or text (pytest's normal assert would print both).
    The frame is hidden from tracebacks too: pytest prints a frame's ARGUMENTS in long tracebacks."""
    __tracebackhide__ = True
    haystack = "\n".join(str(t) for t in texts)
    leaked = sorted(name for name, value in (needles.items() if isinstance(needles, dict) else enumerate(needles)) if value in haystack)
    if leaked:
        raise AssertionError(f"sensitive value(s) present: {leaked} (values deliberately not shown)")


def xml_4688(command_line):
    escaped = command_line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID>
<TimeCreated SystemTime="2026-03-05T09:00:00.000000000Z"/><EventRecordID>5001</EventRecordID><Computer>FIXTURE-PC</Computer></System>
<EventData>
<Data Name="SubjectUserSid">S-1-5-21-1111111111-2222222222-3333333333-1001</Data><Data Name="SubjectUserName">test.fixture.user</Data>
<Data Name="SubjectDomainName">FIXTURE</Data><Data Name="SubjectLogonId">0x3e7</Data>
<Data Name="NewProcessId">0x1a4c</Data><Data Name="NewProcessName">C:\\tools\\deploy.exe</Data>
<Data Name="TokenElevationType">%%1936</Data><Data Name="ProcessId">0x8f0</Data>
<Data Name="CommandLine">{escaped}</Data>
<Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
<Data Name="UnexpectedFutureField">{SECRETS["plain"]}</Data>
</EventData></Event>"""


def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


# ---------------------------------------------------------------- the parser / normalizer


@pytest.mark.parametrize("index", range(len(COMMAND_LINES)), ids=[f"cmdline-{i}" for i in range(len(COMMAND_LINES))])
def test_a_real_process_event_with_a_secret_command_line_is_normalized_without_it(index):
    command_line = COMMAND_LINES[index]  # tests receive an opaque index, never the secret-bearing string
    parsed = parse_event_xml(xml_4688(command_line))
    assert parsed["raw_event_data"]["CommandLine"] == command_line  # the raw parse still sees it in memory...
    event = normalize_event(parsed)
    assert "CommandLine" not in event["raw_event_data"]  # ...but nothing that leaves normalize_event does
    assert "UnexpectedFutureField" not in event["raw_event_data"]
    assert_absent(SECRETS, json.dumps(event))
    # the legitimate process facts are all still there
    assert event["process_name"] == "C:\\tools\\deploy.exe" and event["username"] == "test.fixture.user"
    assert event["parent_process_name"] == "C:\\Windows\\explorer.exe" and event["event_category"] == "process_activity"
    assert event["raw_event_data"]["NewProcessName"] == "C:\\tools\\deploy.exe"


# ---------------------------------------------------------------- the sanitizer itself


def test_only_allowlisted_string_fields_survive():
    raw = {
        "CommandLine": COMMAND_LINES[0], "commandline": COMMAND_LINES[0], "COMMANDLINE": COMMAND_LINES[0],
        "CommandLineArgs": "x", "Password": SECRETS["plain"], "Token": SECRETS["github"], "Anything": "y",
        "TargetUserName": "bob", "LogonType": "2", "IpAddress": None,
        "NewProcessName": {"nested": SECRETS["plain"]}, "ProcessId": ["0x1"], "ObjectName": 12345,
    }
    clean = event_sanitizer.sanitize_raw_event_data(raw)
    assert clean == {"TargetUserName": "bob", "LogonType": "2", "IpAddress": None}
    assert_absent(SECRETS, json.dumps(clean))


def test_sanitizer_never_raises_on_hostile_input_and_does_not_mutate():
    for hostile in (None, "text", 5, [("CommandLine", "x")], {1: "a", None: "b", ("t",): "c"}):
        assert isinstance(event_sanitizer.sanitize_raw_event_data(hostile), dict)
    original = {"CommandLine": "x", "TargetUserName": "bob"}
    event_sanitizer.sanitize_raw_event_data(original)
    assert original == {"CommandLine": "x", "TargetUserName": "bob"}
    many = {f"F{i}": "v" for i in range(500)} | {"TargetUserName": "bob"}
    assert len(event_sanitizer.sanitize_raw_event_data(many)) <= event_sanitizer.MAX_FIELDS
    assert len(event_sanitizer.sanitize_raw_event_data({"ObjectName": "a" * 100_000})["ObjectName"]) == event_sanitizer.MAX_VALUE_CHARS


def test_secret_looking_content_inside_allowed_fields_is_masked_and_benign_text_is_not():
    raw = {
        "ObjectName": f"C:\\data\\backup_password={SECRETS['password']}.txt",
        "AccessList": f"token: {SECRETS['github']} and Bearer {SECRETS['jwt']}",
        "FailureReason": f"--api-key {SECRETS['api']} rejected, key AKIAIOSFODNN7EXAMPLE",
        "ProcessName": "C:\\Program Files\\Tools\\token-viewer.exe",
        "DeviceDescription": "USB Mass Storage Device",
        "NewProcessName": "C:\\Users\\bob\\Documents\\passwords.xlsx",
    }
    clean = event_sanitizer.sanitize_raw_event_data(raw)
    assert_absent(SECRETS, json.dumps(clean))
    assert event_sanitizer.REDACTED in clean["ObjectName"] and event_sanitizer.REDACTED in clean["AccessList"]
    assert clean["ProcessName"] == raw["ProcessName"] and clean["DeviceDescription"] == raw["DeviceDescription"]
    assert clean["NewProcessName"] == raw["NewProcessName"]  # a file NAME containing "passwords" is not a secret assignment
    assert event_sanitizer.sanitize_raw_event_data(clean) == clean  # idempotent


def test_every_allowlisted_field_name_is_a_plain_windows_field_and_commandline_is_not_one_of_them():
    assert "CommandLine" not in event_sanitizer.RAW_FIELD_ALLOWLIST
    # Any allowlisted name that merely LOOKS sensitive must be a conscious, reviewed exception:
    # these three are harmless Windows flags/lengths (an elevation flag, an elevation type, an NTLM key length).
    sensitive_looking = {f for f in event_sanitizer.RAW_FIELD_ALLOWLIST
                         if any(w in f.lower() for w in ("command", "pass", "secret", "token", "credential", "key", "auth"))}
    assert sensitive_looking <= {"ElevatedToken", "TokenElevationType", "KeyLength", "AuthenticationPackageName"}


# ---------------------------------------------------------------- persistence (the last line of defence)


def legacy_agent_event(command_line):
    """What an OLDER agent (or a modified one) would send: raw data exactly as Windows gave it."""
    return {
        "event_id": 4688, "event_record_id": 7001, "event_type": "process_creation", "event_category": "process_activity",
        "timestamp": "2026-03-05T09:00:00.000000Z", "computer_name": "FIXTURE-PC", "username": "test.fixture.user",
        "process_name": f"C:\\tools\\deploy.exe --password {SECRETS['password']}",
        "parent_process_name": "C:\\Windows\\explorer.exe", "process_id": "0x1a4c",
        "raw_event_data": {"CommandLine": command_line, "NewProcessName": "C:\\tools\\deploy.exe", "Extra": SECRETS["plain"],
                           "Nested": {"CommandLine": command_line}},
    }


@pytest.mark.parametrize("index", range(len(COMMAND_LINES)), ids=[f"cmdline-{i}" for i in range(len(COMMAND_LINES))])
def test_storage_never_persists_a_command_line_even_from_an_old_or_modified_agent(index):
    command_line = COMMAND_LINES[index]
    s = session()
    assert insert_event(s, legacy_agent_event(command_line), log_name="Security") == "inserted"
    row = s.query(EventRecord).one()
    everything = json.dumps({c.name: str(getattr(row, c.name)) for c in EventRecord.__table__.columns})
    assert_absent(SECRETS, everything, json.dumps(event_record_to_dict(row)))
    stored_raw = json.loads(row.raw_event_data)
    assert "CommandLine" not in stored_raw and "Extra" not in stored_raw and stored_raw["NewProcessName"] == "C:\\tools\\deploy.exe"
    assert "deploy.exe" in row.process_name and event_sanitizer.REDACTED in row.process_name  # smuggled argument masked, path kept


def test_storage_input_event_is_not_mutated():
    event = legacy_agent_event(COMMAND_LINES[0])
    insert_event(session(), event, log_name="Security")
    assert event["raw_event_data"]["CommandLine"] == COMMAND_LINES[0]


def test_sanitizing_does_not_disturb_deduplication():
    s = session()
    assert insert_event(s, legacy_agent_event(COMMAND_LINES[0]), log_name="Security") == "inserted"
    assert insert_event(s, legacy_agent_event(COMMAND_LINES[1]), log_name="Security") == "duplicate"
    assert s.query(EventRecord).count() == 1


# ---------------------------------------------------------------- the helper itself keeps failure output clean


def test_assert_absent_failure_message_never_contains_the_secret():
    with pytest.raises(AssertionError) as caught:
        assert_absent(SECRETS, f"log line with {SECRETS['password']} inside")
    message = str(caught.value)
    assert "password" in message  # names the category...
    assert not any(value in message for value in SECRETS.values())  # ...but never the value
