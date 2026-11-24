"""
Parsing / normalization logic for Windows Security Event Log events.

This module has NO dependency on pywin32 and does no I/O — it only turns the
event XML that Windows itself produces (via the modern Event Log API,
EvtRender with EvtRenderEventXml) into a clean internal dict. Keeping this
separate from collector.py means:

  - It can be unit-tested without a Windows Event Log connection.
  - The same normalization logic can later be reused if events arrive via a
    different transport (e.g. forwarded events, Azure Event Hub) in a later
    phase.

IMPORTANT: fields are only ever taken from what the raw event actually
contains. If a field is absent, the result is `None` — nothing is invented.

Phase 4 note — event categories: this module now normalizes four
categories of Security-log events (authentication, file_activity,
process_activity, device_activity), all through the same public
`normalize_event()` entry point used since Phase 2/3. Every normalized
event carries the FULL set of optional fields (with `None` for whichever
don't apply to its category) so the schema stays uniform across
categories — see log-collector/README.md for the full field reference and
which Windows event IDs/audit policies each category requires.
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from event_sanitizer import sanitize_raw_event_data

# Windows renders event XML in this namespace.
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Event IDs this project currently cares about, and the human-readable
# event_type each maps to.
EVENT_TYPE_MAP: dict[int, str] = {
    # Authentication (Security log, audited by default)
    4624: "successful_logon",
    4625: "failed_logon",
    4634: "logoff",
    4647: "user_initiated_logoff",
    # File activity (Security log, Object Access auditing — requires
    # "Audit Object Access" > "File System" policy AND a SACL on the
    # specific folder being monitored; see README).
    4656: "file_handle_requested",
    4660: "file_deleted",
    4663: "file_accessed",
    # Process activity (Security log, requires "Audit Process Creation").
    4688: "process_created",
    # Device activity (Security log, requires "Audit PNP Activity").
    6416: "device_recognized",
}

# Which broad category each event ID belongs to. Anything not listed here
# normalizes with event_category="uncategorized" rather than being dropped.
EVENT_CATEGORY_MAP: dict[int, str] = {
    4624: "authentication",
    4625: "authentication",
    4634: "authentication",
    4647: "authentication",
    4656: "file_activity",
    4660: "file_activity",
    4663: "file_activity",
    4688: "process_activity",
    6416: "device_activity",
}

# What each file-activity event ID represents. Deliberately coarse: Windows
# exposes finer-grained detail only via AccessMask/AccessList, which uses
# localized message-table strings that are unreliable to decode generically
# — see README "Known limitations" for why this project does not attempt
# to distinguish created/modified/read at that level.
FILE_ACTION_MAP: dict[int, str] = {
    4656: "handle_requested",
    4660: "deleted",
    4663: "accessed",
}

# Every optional field any category can populate. Every normalized event
# includes all of these keys (None if not applicable to its category) so
# downstream code (validation, storage) never has to special-case which
# keys exist for which category.
_ALL_OPTIONAL_FIELDS: dict[str, Any] = {
    "username": None,
    "domain": None,
    "user_sid": None,
    # authentication-specific
    "logon_type": None,
    "logon_type_description": None,
    "source_ip": None,
    "source_port": None,
    "workstation_name": None,
    "subject_username": None,
    "subject_domain": None,
    "failure_reason": None,
    # file_activity-specific (also used by download_related)
    "file_path": None,
    "file_extension": None,
    "object_type": None,
    "file_action": None,
    "process_name": None,
    "access_list_raw": None,
    # process_activity-specific
    "process_id": None,
    "parent_process_id": None,
    "parent_process_name": None,
    # device_activity-specific
    "device_id": None,
    "device_description": None,
    "device_class": None,
    "device_action": None,
}

# Standard Windows logon type codes (documented by Microsoft).
LOGON_TYPE_MAP: dict[int, str] = {
    2: "interactive",
    3: "network",
    4: "batch",
    5: "service",
    7: "unlock",
    8: "network_cleartext",
    9: "new_credentials",
    10: "remote_interactive",
    11: "cached_interactive",
}

# Well-known SIDs for built-in non-human accounts. Checking the SID (rather
# than the localized username) is the reliable way to detect these, since
# "SYSTEM" / "LOCAL SERVICE" / "NETWORK SERVICE" names are localized on
# non-English Windows installs but these SIDs are not.
_WELL_KNOWN_SYSTEM_SIDS: dict[str, str] = {
    "S-1-5-18": "system",
    "S-1-5-19": "local_service",
    "S-1-5-20": "network_service",
    "S-1-5-7": "anonymous_logon",
}

# Per-SESSION virtual service accounts Windows creates automatically for the
# Desktop Window Manager and Font Driver Host. Microsoft documents these SID
# prefixes as "S-1-5-90-0-<session>" (DWM) and "S-1-5-96-0-<session>" (UMFD)
# — the trailing session number varies per logon session, so this is a
# prefix check, not an exact-SID lookup like the table above.
_VIRTUAL_SERVICE_ACCOUNT_SID_PREFIXES: tuple[str, ...] = ("S-1-5-90-0-", "S-1-5-96-0-")
# Fallback by name, in case a SID wasn't captured for the event (Windows
# names these accounts "DWM-<n>" / "UMFD-<n>" regardless of locale).
_VIRTUAL_SERVICE_ACCOUNT_NAME_PREFIXES: tuple[str, ...] = ("DWM-", "UMFD-")

# Phase 11: per-service SIDs ("NT SERVICE\<name>", documented prefix
# S-1-5-80-). These identify a Windows service's own identity, never a
# person — a tightening of the non-human rules, never a loosening.
_WINDOWS_SERVICE_SID_PREFIX = "S-1-5-80-"

# Phase 11: the NULL SID ("Nobody"). Windows writes it as TargetUserSid on
# events where no real account was resolved — most importantly 4625 failed
# logons for a mistyped/nonexistent user name. It identifies nobody, so it
# is treated as "no SID provided" rather than a real account identifier
# (otherwise every such failed logon, for every attempted name, would be
# collapsed into one pseudo-user "S-1-0-0" downstream).
NULL_SID = "S-1-0-0"

# Human-readable explanation for each classify_account() return value — used
# by diagnostics (ml-service/user_classification_diagnostics.py) to explain
# WHY a given account was or wasn't treated as a human candidate, without
# duplicating this reasoning in a second place.
ACCOUNT_TYPE_EXPLANATIONS: dict[str, str] = {
    "system": "Well-known Windows SYSTEM account (SID S-1-5-18, or name match) — not a human user.",
    "local_service": "Well-known Windows LOCAL SERVICE account (SID S-1-5-19, or name match) — not a human user.",
    "network_service": "Well-known Windows NETWORK SERVICE account (SID S-1-5-20, or name match) — not a human user.",
    "anonymous_logon": "Well-known Windows ANONYMOUS LOGON identity (SID S-1-5-7) — not a human user.",
    "virtual_service_account": (
        "Per-session virtual service account created automatically by Windows "
        "(Desktop Window Manager 'DWM-n' or Font Driver Host 'UMFD-n') — not a human user."
    ),
    "computer_account": "Computer/machine account (name ends with '$') — not a human user.",
    "windows_service_account": (
        "Per-service Windows identity (NT SERVICE\\<name>, SID prefix S-1-5-80-) — not a human user."
    ),
    "human_or_unknown": (
        "No known non-human signal (well-known SID, virtual-account pattern, or "
        "computer-account suffix) matched this account — treated as a human candidate. "
        "This is a best-effort absence-of-evidence classification, not positive proof "
        "of a human."
    ),
    "unknown": "No username or SID was present in the underlying Windows event — cannot attribute this event to any account.",
}


def classify_account(username: str | None, user_sid: str | None) -> str:
    """Best-effort classification of the account referenced by an event.

    This is intentionally coarse and conservative: it only ever asserts
    "not human" when a specific, documented Windows signal supports it
    (a well-known SID, a well-known virtual-account naming pattern, or the
    '$' computer-account suffix). Everything else falls through to
    "human_or_unknown" — which is an absence of a negative signal, not
    positive proof of a human. Deciding which of those candidates represent
    real human behavior for analysis purposes is deferred to a later phase.
    """
    if user_sid:
        if user_sid in _WELL_KNOWN_SYSTEM_SIDS:
            return _WELL_KNOWN_SYSTEM_SIDS[user_sid]
        if user_sid.startswith(_VIRTUAL_SERVICE_ACCOUNT_SID_PREFIXES):
            return "virtual_service_account"
        if user_sid.startswith(_WINDOWS_SERVICE_SID_PREFIX):
            return "windows_service_account"
    if username:
        cleaned = username.strip()
        if cleaned.endswith("$"):
            return "computer_account"
        upper = cleaned.upper()
        if upper in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}:
            return "system"
        if upper == "ANONYMOUS LOGON":
            return "anonymous_logon"
        if upper.startswith(_VIRTUAL_SERVICE_ACCOUNT_NAME_PREFIXES):
            return "virtual_service_account"
        return "human_or_unknown"
    return "unknown"


def _text(el: ET.Element | None) -> str | None:
    return el.text if el is not None else None


def _clean(value: str | None) -> str | None:
    """Windows commonly uses '-' as a placeholder for "not applicable".
    Treat that as no value rather than fabricating meaning for it."""
    if value is None:
        return None
    stripped = value.strip()
    if stripped in ("", "-"):
        return None
    return stripped


def _clean_sid(value: str | None) -> str | None:
    """Like _clean, but also treats the NULL SID (S-1-0-0) as absent — see
    NULL_SID above. Never invents a SID; only declines to use a placeholder
    one as an identity."""
    cleaned = _clean(value)
    if cleaned == NULL_SID:
        return None
    return cleaned


def parse_event_xml(xml_str: str) -> dict[str, Any]:
    """Parse the raw XML returned by EvtRender(EvtRenderEventXml) into a
    generic structure: System-level fields plus a dict of every named
    EventData field, exactly as Windows reported them."""
    root = ET.fromstring(xml_str)
    system = root.find("e:System", _NS)

    event_id = None
    if system is not None:
        event_id_el = system.find("e:EventID", _NS)
        if event_id_el is not None and event_id_el.text is not None:
            event_id = int(event_id_el.text)

    timestamp = None
    computer_name = None
    event_record_id: int | str | None = None
    if system is not None:
        time_created_el = system.find("e:TimeCreated", _NS)
        if time_created_el is not None:
            timestamp = time_created_el.get("SystemTime")
        computer_name = _text(system.find("e:Computer", _NS))

        record_id_el = system.find("e:EventRecordID", _NS)
        if record_id_el is not None and record_id_el.text is not None:
            try:
                event_record_id = int(record_id_el.text)
            except ValueError:
                event_record_id = record_id_el.text  # keep raw value rather than dropping it

    raw_event_data: dict[str, str | None] = {}
    event_data_el = root.find("e:EventData", _NS)
    if event_data_el is not None:
        for data_el in event_data_el.findall("e:Data", _NS):
            name = data_el.get("Name")
            if name:
                raw_event_data[name] = data_el.text

    return {
        "event_id": event_id,
        "event_record_id": event_record_id,
        "timestamp": timestamp,
        "computer_name": computer_name,
        "raw_event_data": raw_event_data,
    }


def _base_fields() -> dict[str, Any]:
    return dict(_ALL_OPTIONAL_FIELDS)


def _normalize_authentication_fields(event_id: int | None, data: dict[str, str | None]) -> dict[str, Any]:
    fields = _base_fields()
    fields["username"] = _clean(data.get("TargetUserName"))
    fields["domain"] = _clean(data.get("TargetDomainName"))
    fields["user_sid"] = _clean_sid(data.get("TargetUserSid"))

    logon_type_raw = _clean(data.get("LogonType"))
    if logon_type_raw is not None:
        try:
            fields["logon_type"] = int(logon_type_raw)
            fields["logon_type_description"] = LOGON_TYPE_MAP.get(fields["logon_type"])
        except ValueError:
            fields["logon_type"] = logon_type_raw  # keep raw value rather than dropping it

    fields["source_ip"] = _clean(data.get("IpAddress"))
    fields["source_port"] = _clean(data.get("IpPort"))
    fields["workstation_name"] = _clean(data.get("WorkstationName"))
    fields["subject_username"] = _clean(data.get("SubjectUserName"))
    fields["subject_domain"] = _clean(data.get("SubjectDomainName"))

    if event_id == 4625:
        fields["failure_reason"] = (
            _clean(data.get("FailureReason"))
            or _clean(data.get("Status"))
            or _clean(data.get("SubStatus"))
        )
    return fields


def _normalize_file_activity_fields(event_id: int | None, data: dict[str, str | None]) -> dict[str, Any]:
    """Object Access ("File System") audit events: 4656 (handle requested),
    4663 (access attempt), 4660 (object deleted). The account here is the
    SUBJECT (who performed the action) — file events have no "target user"
    concept the way logons do."""
    fields = _base_fields()
    fields["username"] = _clean(data.get("SubjectUserName"))
    fields["domain"] = _clean(data.get("SubjectDomainName"))
    fields["user_sid"] = _clean_sid(data.get("SubjectUserSid"))

    file_path = _clean(data.get("ObjectName"))
    fields["file_path"] = file_path
    if file_path:
        _, ext = os.path.splitext(file_path)
        fields["file_extension"] = ext.lower() if ext else None
    fields["object_type"] = _clean(data.get("ObjectType"))
    fields["file_action"] = FILE_ACTION_MAP.get(event_id) if event_id is not None else None
    fields["process_name"] = _clean(data.get("ProcessName"))
    # Kept as a raw string rather than decoded — see FILE_ACTION_MAP comment.
    fields["access_list_raw"] = _clean(data.get("AccessList"))
    return fields


def _normalize_process_activity_fields(data: dict[str, str | None]) -> dict[str, Any]:
    """Process Creation audit event (4688). "ProcessId" in this event's raw
    schema is the CREATING (parent) process; "NewProcessId"/"NewProcessName"
    are the process actually being created."""
    fields = _base_fields()
    fields["username"] = _clean(data.get("SubjectUserName"))
    fields["domain"] = _clean(data.get("SubjectDomainName"))
    fields["user_sid"] = _clean_sid(data.get("SubjectUserSid"))
    fields["process_name"] = _clean(data.get("NewProcessName"))
    fields["process_id"] = _clean(data.get("NewProcessId"))
    fields["parent_process_id"] = _clean(data.get("ProcessId"))
    fields["parent_process_name"] = _clean(data.get("ParentProcessName"))
    # NOTE: Windows only includes a "CommandLine" field here if the
    # "Include command line in process creation events" policy is enabled
    # (it is NOT enabled by default). This project does not promote it to
    # a first-class column — if present, it is only ever visible inside
    # raw_event_data. See README Privacy section.
    return fields


def _normalize_device_activity_fields(data: dict[str, str | None]) -> dict[str, Any]:
    """PNP Activity audit event (6416 — "a new external device was
    recognized"). This subcategory only reports device recognition/connect;
    see README for why disconnect is not covered in this phase."""
    fields = _base_fields()
    fields["username"] = _clean(data.get("SubjectUserName"))
    fields["domain"] = _clean(data.get("SubjectDomainName"))
    fields["user_sid"] = _clean_sid(data.get("SubjectUserSid"))
    fields["device_id"] = _clean(data.get("DeviceId"))
    fields["device_description"] = _clean(data.get("DeviceDescription"))
    fields["device_class"] = _clean(data.get("ClassName"))
    fields["device_action"] = "connected"
    return fields


def normalize_event(parsed: dict[str, Any]) -> dict[str, Any]:
    """Turn the generic parsed structure into the project's normalized
    event representation. Dispatches to a category-specific normalizer
    based on the event ID, but every result carries the same full set of
    keys (see _ALL_OPTIONAL_FIELDS) — unused ones are `None`, never
    guessed."""
    event_id = parsed.get("event_id")
    data: dict[str, str | None] = parsed.get("raw_event_data", {})
    category = EVENT_CATEGORY_MAP.get(event_id, "uncategorized")

    if category == "authentication":
        fields = _normalize_authentication_fields(event_id, data)
    elif category == "file_activity":
        fields = _normalize_file_activity_fields(event_id, data)
    elif category == "process_activity":
        fields = _normalize_process_activity_fields(data)
    elif category == "device_activity":
        fields = _normalize_device_activity_fields(data)
    else:
        fields = _base_fields()

    fields["account_type"] = classify_account(fields.get("username"), fields.get("user_sid"))

    return {
        "event_id": event_id,
        "event_record_id": parsed.get("event_record_id"),
        "event_type": EVENT_TYPE_MAP.get(event_id, f"unhandled_event_{event_id}"),
        "event_category": category,
        "timestamp": parsed.get("timestamp"),
        "computer_name": parsed.get("computer_name"),
        **fields,
        # Only an ALLOWLIST of EventData fields is kept (never CommandLine or other free-form
        # argument strings) - see event_sanitizer.py. The normalizers above already read what they
        # need from the full `data`; this is what leaves memory.
        "raw_event_data": sanitize_raw_event_data(data),
    }


def classify_download(file_path: str | None, downloads_folder: str | None) -> bool:
    """Path-based inference only: True if `file_path` is located under
    `downloads_folder`. This does NOT confirm a browser download occurred —
    it only reflects file-activity location. See README "Download activity"
    section for the full (a)/(b)/(c) distinction this project draws."""
    if not file_path or not downloads_folder:
        return False
    try:
        candidate = Path(file_path).resolve()
        folder = Path(downloads_folder).resolve()
    except (OSError, ValueError):
        return False
    return candidate == folder or folder in candidate.parents
