"""
Privacy guard for collected Windows events (Phase 17 / Stage 4G, finding 3).

Problem this solves: the collector used to keep EVERY named field of a Windows event in
`raw_event_data`, including `CommandLine` of process-creation events (4688) whenever the
"Include command line in process creation events" policy is on. Command lines routinely carry
passwords, tokens and keys. Relying on that policy being off is not a control.

Two layers use this module:
  1. event_parser.normalize_event() - so the agent never buffers or uploads such data;
  2. storage.insert_event()        - so the database never persists it, whichever client (an older
     agent, a modified one, the CLI collector) produced the event.

Method: an ALLOWLIST of Windows field names that describe WHO/WHAT/WHEN/WHERE but not free-form
program arguments. Everything else - CommandLine, unknown fields, nested objects, oversized values -
is dropped. Remaining free-text values additionally have secret-looking `key=value`, `--flag value`,
bearer/JWT and well-known token formats masked. This module never logs values.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "<redacted>"
MAX_VALUE_CHARS = 4096
MAX_FIELDS = 64

# Windows Security event fields for the supported ids (4624/4625/4634/4647 authentication,
# 4656/4660/4663 file, 4688 process, 6416 device). `CommandLine` is deliberately NOT here.
RAW_FIELD_ALLOWLIST: frozenset[str] = frozenset(
    {
        # subject / target identity
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
        "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId",
        "TargetOutboundUserName", "TargetOutboundDomainName", "TargetLinkedLogonId",
        # logon details
        "LogonType", "LogonProcessName", "AuthenticationPackageName", "WorkstationName", "LogonGuid",
        "TransmittedServices", "LmPackageName", "KeyLength", "IpAddress", "IpPort", "ImpersonationLevel",
        "RestrictedAdminMode", "VirtualAccount", "ElevatedToken", "Status", "SubStatus", "FailureReason",
        # process
        "ProcessId", "ProcessName", "NewProcessId", "NewProcessName", "ParentProcessName", "TokenElevationType",
        "MandatoryLabel",
        # object / file access
        "ObjectServer", "ObjectType", "ObjectName", "HandleId", "TransactionId", "AccessList", "AccessReason",
        "AccessMask", "PrivilegeList", "RestrictedSidCount", "ResourceAttributes",
        # device
        "DeviceId", "DeviceDescription", "ClassId", "ClassName", "VendorIds", "CompatibleIds", "LocationInformation",
    }
)

_QUOTED_OR_WORD = r"""(?:"[^"]*"|'[^']*'|\S+)"""
_KEYWORD = r"(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[-_ ]?key|apikey|access[-_ ]?key|private[-_ ]?key|client[-_ ]?secret|auth(?:orization)?|credential)s?"
_PATTERNS: list[tuple[re.Pattern, str]] = [
    # key=value / key: value   (password=hunter2, "token": "abc", AWS_SECRET_ACCESS_KEY=...)
    # (prefix/suffix/space runs are length-bounded so a hostile value cannot cause quadratic backtracking)
    (re.compile(rf"(?i)([\w.-]{{0,40}}{_KEYWORD}[\w.-]{{0,40}})(\"?\s{{0,8}}[=:]\s{{0,8}})({_QUOTED_OR_WORD})"), rf"\1\2{REDACTED}"),
    # --password hunter2 / -token abc / /pass:hunter2 (flag followed by a value)
    (re.compile(rf"(?i)((?:--?|/){_KEYWORD})(\s{{1,8}}|:)({_QUOTED_OR_WORD})"), rf"\1\2{REDACTED}"),
    # Authorization headers and bearer tokens
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"), f"Bearer {REDACTED}"),
    # well-known token shapes
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"), REDACTED),  # JWT
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), REDACTED),  # GitHub
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),  # AWS access key id
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), REDACTED),  # Slack
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}"), REDACTED),  # generic API secret keys
]


# One linear scan for any marker the patterns above could match (superset of their literals).
_QUICK_CHECK = re.compile(r"(?i)pass|pwd|secret|token|key|auth|credential|bearer|eyJ|gh[pousr]_|xox[abprs]-|sk-")


def scrub_text(value: str) -> str:
    """Masks secret-looking content in a free-text value. Idempotent."""
    out = value[:MAX_VALUE_CHARS]  # bound the work FIRST: never run patterns over an attacker-sized string
    if not _QUICK_CHECK.search(out):
        return out  # nothing that could be a secret marker: skip the (costlier) masking passes
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    return out[:MAX_VALUE_CHARS]


def sanitize_raw_event_data(raw: Any) -> dict[str, str | None]:
    """Returns a NEW dict containing only allowlisted fields with string (or null) values, scrubbed.
    Never raises on malformed input (a tampered client may send anything)."""
    if not isinstance(raw, dict):
        return {}
    clean: dict[str, str | None] = {}
    for key, value in raw.items():
        if len(clean) >= MAX_FIELDS:
            break
        if key not in RAW_FIELD_ALLOWLIST:
            continue  # CommandLine, unknown fields, anything not explicitly approved
        if value is None:
            clean[key] = None
        elif isinstance(value, str):
            clean[key] = scrub_text(value)
        # nested objects / numbers / lists are dropped: Windows EventData values are strings
    return clean


# Free-text columns of a normalized event that could carry a smuggled argument string.
_FREE_TEXT_FIELDS = (
    "file_path", "process_name", "parent_process_name", "access_list_raw", "failure_reason",
    "device_description", "device_id", "workstation_name", "source_machine",
)


def sanitize_event_for_storage(event: dict) -> dict:
    """Shallow copy of `event` that is safe to persist: sanitized raw_event_data and scrubbed
    free-text fields. The input is not modified."""
    safe = dict(event)
    safe["raw_event_data"] = sanitize_raw_event_data(event.get("raw_event_data"))
    for field in _FREE_TEXT_FIELDS:
        value = safe.get(field)
        if isinstance(value, str):
            safe[field] = scrub_text(value)
    return safe
