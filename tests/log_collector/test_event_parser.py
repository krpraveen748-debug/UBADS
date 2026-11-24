"""
Unit tests for event_parser.py — the normalization logic only.

The XML fixtures below are PARSER-TEST FIXTURES ONLY.

They are hand-written strings that mimic the *structural shape* of the XML
Windows produces for Security events (per Microsoft's documented schema),
so that parse_event_xml()/normalize_event() can be tested without a live
Windows Event Log connection.

They are NOT real collected data, do not represent any real user, machine,
or account, and must never be treated as project/research data. Real data
only ever comes from collector.py reading the actual local Security log.
"""

from event_parser import classify_account, classify_download, normalize_event, parse_event_xml

# --- PARSER-TEST FIXTURE (not real data) -----------------------------------
FIXTURE_4624_SUCCESSFUL_LOGON = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4624</EventID>
    <EventRecordID>123456</EventRecordID>
    <TimeCreated SystemTime="2026-01-01T10:00:00.000000000Z" />
    <Computer>TEST-FIXTURE-PC</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">-</Data>
    <Data Name="SubjectDomainName">-</Data>
    <Data Name="TargetUserName">test.fixture.user</Data>
    <Data Name="TargetDomainName">FIXTURE-DOMAIN</Data>
    <Data Name="TargetUserSid">S-1-5-21-000000000-000000000-000000000-1001</Data>
    <Data Name="LogonType">2</Data>
    <Data Name="WorkstationName">TEST-FIXTURE-PC</Data>
    <Data Name="IpAddress">-</Data>
    <Data Name="IpPort">0</Data>
  </EventData>
</Event>"""

# --- PARSER-TEST FIXTURE (not real data) -----------------------------------
FIXTURE_4624_SYSTEM_ACCOUNT = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-01-01T10:05:00.000000000Z" />
    <Computer>TEST-FIXTURE-PC</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">SYSTEM</Data>
    <Data Name="TargetDomainName">NT AUTHORITY</Data>
    <Data Name="TargetUserSid">S-1-5-18</Data>
    <Data Name="LogonType">5</Data>
  </EventData>
</Event>"""

# --- PARSER-TEST FIXTURE (not real data) -----------------------------------
FIXTURE_4625_FAILED_LOGON = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-01-01T10:10:00.000000000Z" />
    <Computer>TEST-FIXTURE-PC</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">test.fixture.user</Data>
    <Data Name="TargetDomainName">FIXTURE-DOMAIN</Data>
    <Data Name="Status">0xC000006D</Data>
  </EventData>
</Event>"""

# --- PARSER-TEST FIXTURE (not real data) -----------------------------------
FIXTURE_MISSING_FIELDS = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4634</EventID>
    <Computer>TEST-FIXTURE-PC</Computer>
  </System>
</Event>"""

# --- PARSER-TEST FIXTURE (not real data) -----------------------------------
FIXTURE_4634_LOGOFF = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4634</EventID>
    <EventRecordID>123457</EventRecordID>
    <TimeCreated SystemTime="2026-01-01T10:30:00.000000000Z" />
    <Computer>TEST-FIXTURE-PC</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">test.fixture.user</Data>
    <Data Name="TargetDomainName">FIXTURE-DOMAIN</Data>
    <Data Name="TargetUserSid">S-1-5-21-000000000-000000000-000000000-1001</Data>
    <Data Name="LogonType">2</Data>
  </EventData>
</Event>"""

# --- PARSER-TEST FIXTURE (not real data) -----------------------------------
FIXTURE_4647_USER_INITIATED_LOGOFF = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4647</EventID>
    <EventRecordID>123458</EventRecordID>
    <TimeCreated SystemTime="2026-01-01T10:35:00.000000000Z" />
    <Computer>TEST-FIXTURE-PC</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">test.fixture.user</Data>
    <Data Name="TargetDomainName">FIXTURE-DOMAIN</Data>
    <Data Name="TargetUserSid">S-1-5-21-000000000-000000000-000000000-1001</Data>
  </EventData>
</Event>"""

# --- PARSER-TEST FIXTURE (not real data) -----------------------------------
FIXTURE_4663_FILE_ACCESSED = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4663</EventID>
    <EventRecordID>200001</EventRecordID>
    <TimeCreated SystemTime="2026-01-01T11:00:00.000000000Z" />
    <Computer>TEST-FIXTURE-PC</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-000000000-000000000-000000000-1001</Data>
    <Data Name="SubjectUserName">test.fixture.user</Data>
    <Data Name="SubjectDomainName">FIXTURE-DOMAIN</Data>
    <Data Name="ObjectType">File</Data>
    <Data Name="ObjectName">C:\\Users\\test.fixture.user\\Documents\\UBADS_TestFolder\\report.pdf</Data>
    <Data Name="ProcessName">C:\\Windows\\explorer.exe</Data>
    <Data Name="AccessList">%%4416</Data>
  </EventData>
</Event>"""

# --- PARSER-TEST FIXTURE (not real data) -----------------------------------
FIXTURE_4660_FILE_DELETED = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4660</EventID>
    <EventRecordID>200002</EventRecordID>
    <TimeCreated SystemTime="2026-01-01T11:05:00.000000000Z" />
    <Computer>TEST-FIXTURE-PC</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-000000000-000000000-000000000-1001</Data>
    <Data Name="SubjectUserName">test.fixture.user</Data>
    <Data Name="SubjectDomainName">FIXTURE-DOMAIN</Data>
    <Data Name="ObjectType">File</Data>
  </EventData>
</Event>"""

# --- PARSER-TEST FIXTURE (not real data) -----------------------------------
FIXTURE_4688_PROCESS_CREATED = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4688</EventID>
    <EventRecordID>300001</EventRecordID>
    <TimeCreated SystemTime="2026-01-01T12:00:00.000000000Z" />
    <Computer>TEST-FIXTURE-PC</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-000000000-000000000-000000000-1001</Data>
    <Data Name="SubjectUserName">test.fixture.user</Data>
    <Data Name="SubjectDomainName">FIXTURE-DOMAIN</Data>
    <Data Name="NewProcessId">0x1a2b</Data>
    <Data Name="NewProcessName">C:\\Windows\\System32\\notepad.exe</Data>
    <Data Name="ProcessId">0x3c4d</Data>
    <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
  </EventData>
</Event>"""

# --- PARSER-TEST FIXTURE (not real data) -----------------------------------
FIXTURE_6416_DEVICE_RECOGNIZED = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>6416</EventID>
    <EventRecordID>400001</EventRecordID>
    <TimeCreated SystemTime="2026-01-01T13:00:00.000000000Z" />
    <Computer>TEST-FIXTURE-PC</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-000000000-000000000-000000000-1001</Data>
    <Data Name="SubjectUserName">test.fixture.user</Data>
    <Data Name="SubjectDomainName">FIXTURE-DOMAIN</Data>
    <Data Name="DeviceId">USBSTOR\\Disk&amp;Ven_Fixture&amp;Prod_TestDrive\\0001</Data>
    <Data Name="DeviceDescription">Fixture Test USB Drive</Data>
    <Data Name="ClassName">DiskDrive</Data>
  </EventData>
</Event>"""


def test_parse_event_xml_extracts_system_and_event_data():
    parsed = parse_event_xml(FIXTURE_4624_SUCCESSFUL_LOGON)
    assert parsed["event_id"] == 4624
    assert parsed["event_record_id"] == 123456
    assert parsed["computer_name"] == "TEST-FIXTURE-PC"
    assert parsed["timestamp"] == "2026-01-01T10:00:00.000000000Z"
    assert parsed["raw_event_data"]["TargetUserName"] == "test.fixture.user"


def test_normalize_successful_logon():
    parsed = parse_event_xml(FIXTURE_4624_SUCCESSFUL_LOGON)
    normalized = normalize_event(parsed)

    assert normalized["event_type"] == "successful_logon"
    assert normalized["event_category"] == "authentication"
    assert normalized["event_record_id"] == 123456
    assert normalized["username"] == "test.fixture.user"
    assert normalized["domain"] == "FIXTURE-DOMAIN"
    assert normalized["logon_type"] == 2
    assert normalized["logon_type_description"] == "interactive"
    assert normalized["account_type"] == "human_or_unknown"
    # "-" placeholders must be normalized to None, not kept as literal text.
    assert normalized["source_ip"] is None


def test_normalize_identifies_system_account_by_sid():
    parsed = parse_event_xml(FIXTURE_4624_SYSTEM_ACCOUNT)
    normalized = normalize_event(parsed)

    assert normalized["account_type"] == "system"
    assert normalized["logon_type_description"] == "service"


def test_normalize_failed_logon_captures_failure_reason():
    parsed = parse_event_xml(FIXTURE_4625_FAILED_LOGON)
    normalized = normalize_event(parsed)

    assert normalized["event_type"] == "failed_logon"
    assert normalized["failure_reason"] == "0xC000006D"
    assert normalized["event_category"] == "authentication"


def test_normalize_logoff_event():
    parsed = parse_event_xml(FIXTURE_4634_LOGOFF)
    normalized = normalize_event(parsed)

    assert normalized["event_type"] == "logoff"
    assert normalized["event_category"] == "authentication"
    assert normalized["username"] == "test.fixture.user"
    assert normalized["account_type"] == "human_or_unknown"


def test_normalize_user_initiated_logoff_event():
    parsed = parse_event_xml(FIXTURE_4647_USER_INITIATED_LOGOFF)
    normalized = normalize_event(parsed)

    assert normalized["event_type"] == "user_initiated_logoff"
    assert normalized["event_category"] == "authentication"
    assert normalized["username"] == "test.fixture.user"


def test_normalize_handles_missing_fields_as_none_not_invented():
    parsed = parse_event_xml(FIXTURE_MISSING_FIELDS)
    normalized = normalize_event(parsed)

    assert normalized["event_type"] == "logoff"
    assert normalized["username"] is None
    assert normalized["logon_type"] is None
    assert normalized["source_ip"] is None


def test_classify_account_well_known_sid():
    assert classify_account("anything", "S-1-5-19") == "local_service"


def test_classify_account_computer_account_suffix():
    assert classify_account("TEST-FIXTURE-PC$", None) == "computer_account"


def test_classify_account_unknown_when_no_data():
    assert classify_account(None, None) == "unknown"


def test_classify_account_anonymous_logon_by_sid():
    assert classify_account("anything", "S-1-5-7") == "anonymous_logon"


def test_classify_account_anonymous_logon_by_name_fallback():
    assert classify_account("ANONYMOUS LOGON", None) == "anonymous_logon"


def test_classify_account_dwm_virtual_account_by_sid():
    # Real, documented Windows SID prefix for per-session DWM accounts —
    # the trailing number varies per logon session.
    assert classify_account("DWM-2", "S-1-5-90-0-2") == "virtual_service_account"


def test_classify_account_umfd_virtual_account_by_name_fallback():
    # No SID captured for this event — falls back to the documented naming
    # pattern Windows uses for Font Driver Host per-session accounts.
    assert classify_account("UMFD-1", None) == "virtual_service_account"


def test_classify_account_genuine_human_like_account_is_human_or_unknown():
    # A normal domain-joined user SID (S-1-5-21-<domain>-<rid>) with an
    # ordinary username — matches none of the known non-human signals, so
    # this is the conservative "human candidate" fallback.
    result = classify_account(
        "test.fixture.human.user", "S-1-5-21-1111111111-2222222222-3333333333-1001"
    )
    assert result == "human_or_unknown"


def test_classify_account_does_not_assume_human_just_because_not_a_known_service_sid():
    # An unrecognized SID pattern alone is not treated as proof of anything
    # — this only becomes human_or_unknown because a username was ALSO
    # present. Documents the conservative-fallback boundary explicitly.
    result = classify_account("someaccount", "S-1-5-21-9999999999-8888888888-7777777777-500")
    assert result == "human_or_unknown"


def test_classify_account_windows_service_sid():
    # Phase 11: NT SERVICE\<name> identities, documented SID prefix
    # S-1-5-80- — a service's own identity, never a human.
    assert classify_account("NT SERVICE\\Schedule", "S-1-5-80-1234567890-1") == "windows_service_account"


def test_classify_account_null_sid_is_not_a_human_signal_either_way():
    # Phase 11: the NULL SID (S-1-0-0) means "no account resolved" (e.g. a
    # 4625 failed logon for a nonexistent username) — never a positive
    # human signal, and never a stable pseudo-identity to key on.
    result = classify_account("some.mistyped.name", "S-1-0-0")
    assert result == "human_or_unknown"  # falls through on the USERNAME, not the SID


def test_normalize_strips_null_sid_from_user_sid_field():
    # The normalized event's user_sid must not surface S-1-0-0 as if it
    # were a real, usable identifier (see ml-service/user_identity.py,
    # which prefers user_sid over username when present).
    parsed = {
        "event_id": 4625,
        "event_record_id": 1,
        "timestamp": "2026-01-01T00:00:00Z",
        "computer_name": "TEST-FIXTURE-PC",
        "raw_event_data": {
            "TargetUserName": "mistyped.user",
            "TargetUserSid": "S-1-0-0",
        },
    }
    normalized = normalize_event(parsed)
    assert normalized["user_sid"] is None
    assert normalized["username"] == "mistyped.user"


def test_normalize_file_accessed_event():
    parsed = parse_event_xml(FIXTURE_4663_FILE_ACCESSED)
    normalized = normalize_event(parsed)

    assert normalized["event_type"] == "file_accessed"
    assert normalized["event_category"] == "file_activity"
    assert normalized["username"] == "test.fixture.user"
    assert normalized["file_path"].endswith("report.pdf")
    assert normalized["file_extension"] == ".pdf"
    assert normalized["file_action"] == "accessed"
    assert normalized["object_type"] == "File"
    assert normalized["process_name"] == r"C:\Windows\explorer.exe"
    assert normalized["access_list_raw"] == "%%4416"
    # Fields from other categories must stay None, never guessed.
    assert normalized["logon_type"] is None
    assert normalized["process_id"] is None


def test_normalize_file_deleted_event_with_no_path_field():
    parsed = parse_event_xml(FIXTURE_4660_FILE_DELETED)
    normalized = normalize_event(parsed)

    assert normalized["event_type"] == "file_deleted"
    assert normalized["file_action"] == "deleted"
    # This fixture omits ObjectName on purpose — must be None, not invented.
    assert normalized["file_path"] is None
    assert normalized["file_extension"] is None


def test_normalize_process_created_event():
    parsed = parse_event_xml(FIXTURE_4688_PROCESS_CREATED)
    normalized = normalize_event(parsed)

    assert normalized["event_type"] == "process_created"
    assert normalized["event_category"] == "process_activity"
    assert normalized["username"] == "test.fixture.user"
    assert normalized["process_name"] == r"C:\Windows\System32\notepad.exe"
    assert normalized["process_id"] == "0x1a2b"
    assert normalized["parent_process_id"] == "0x3c4d"
    assert normalized["parent_process_name"] == r"C:\Windows\explorer.exe"
    # No command-line field is promoted to a first-class column.
    assert "command_line" not in normalized


def test_normalize_device_recognized_event():
    parsed = parse_event_xml(FIXTURE_6416_DEVICE_RECOGNIZED)
    normalized = normalize_event(parsed)

    assert normalized["event_type"] == "device_recognized"
    assert normalized["event_category"] == "device_activity"
    assert normalized["device_description"] == "Fixture Test USB Drive"
    assert normalized["device_class"] == "DiskDrive"
    assert normalized["device_action"] == "connected"
    assert normalized["username"] == "test.fixture.user"


def test_normalize_uncategorized_event_id_is_not_dropped():
    parsed = {
        "event_id": 9999,
        "event_record_id": 1,
        "timestamp": "2026-01-01T00:00:00.000000Z",
        "computer_name": "TEST-FIXTURE-PC",
        "raw_event_data": {},
    }
    normalized = normalize_event(parsed)
    assert normalized["event_category"] == "uncategorized"
    assert normalized["event_type"] == "unhandled_event_9999"


def test_classify_download_true_for_path_under_downloads_folder():
    assert classify_download(
        r"C:\Users\test.fixture.user\Downloads\installer.exe",
        r"C:\Users\test.fixture.user\Downloads",
    )


def test_classify_download_false_for_path_outside_downloads_folder():
    assert not classify_download(
        r"C:\Users\test.fixture.user\Documents\report.pdf",
        r"C:\Users\test.fixture.user\Downloads",
    )


def test_classify_download_false_when_no_folder_configured():
    assert not classify_download(r"C:\Users\test.fixture.user\Downloads\file.zip", None)


def test_classify_download_false_when_no_file_path():
    assert not classify_download(None, r"C:\Users\test.fixture.user\Downloads")
