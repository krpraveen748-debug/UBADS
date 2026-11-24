"""
Validation for normalized events, before they are handed to the storage
layer.

Design: a small set of fields are REQUIRED because the rest of the pipeline
(deduplication, storage, future feature engineering) cannot function
without them. Everything else is OPTIONAL — Windows legitimately omits many
fields depending on event type/configuration, and an event is never
rejected just because an optional field is missing (only `None`).

Required (blocks storage if missing/invalid):
  - event_id        (must be present and an int)
  - timestamp       (must be present and parseable as a real date/time)
  - computer_name   (must be present and non-empty)
  - event_type      (must be present and a non-empty string)

Optional (missing is fine; only flagged as a WARNING if present but
malformed, e.g. an empty string rather than an absent value):
  - username, domain, user_sid, account_type, logon_type,
    logon_type_description, source_ip, workstation_name,
    subject_username, subject_domain, failure_reason, event_record_id
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


def parse_utc_timestamp(value: str | None) -> datetime | None:
    """Parse a Windows event timestamp string into a timezone-aware UTC
    datetime. Windows' TimeCreated/SystemTime attribute is always UTC
    already (that's Microsoft's documented behavior for this field) — this
    function does not shift the time, it only attaches the UTC timezone so
    the value is unambiguous, and validates that it is a real timestamp.
    Returns None if the value is missing or not a valid ISO-8601 timestamp.
    """
    if not value:
        return None
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass
class ValidationResult:
    is_valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def validate_event(event: dict) -> ValidationResult:
    """Validate a normalized event dict (as produced by
    event_parser.normalize_event). Never mutates the input."""
    errors: list[str] = []
    warnings: list[str] = []

    event_id = event.get("event_id")
    if event_id is None:
        errors.append("missing_event_id")
    elif not isinstance(event_id, int):
        errors.append("invalid_event_id_type")

    timestamp = event.get("timestamp")
    if not timestamp:
        errors.append("missing_timestamp")
    elif parse_utc_timestamp(timestamp) is None:
        errors.append("invalid_timestamp")

    computer_name = event.get("computer_name")
    if not computer_name or not str(computer_name).strip():
        errors.append("missing_computer_name")

    event_type = event.get("event_type")
    if not event_type or not isinstance(event_type, str):
        errors.append("invalid_event_type")

    username = event.get("username")
    if username is not None and not str(username).strip():
        warnings.append("empty_username_string")

    logon_type = event.get("logon_type")
    if logon_type is not None and not isinstance(logon_type, int):
        warnings.append("unexpected_logon_type_format")

    return ValidationResult(is_valid=(len(errors) == 0), errors=errors, warnings=warnings)
