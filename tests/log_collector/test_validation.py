"""
Unit tests for validation.py.

The event dicts below are VALIDATION-TEST FIXTURES ONLY — hand-written
normalized-event-shaped dicts used to exercise the validation rules. They
are not real collected data and do not represent any real user or machine.
"""

from datetime import timezone

from validation import parse_utc_timestamp, validate_event


def _valid_event(**overrides):
    base = {
        "event_id": 4624,
        "event_type": "successful_logon",
        "timestamp": "2026-01-01T10:00:00.000000Z",
        "computer_name": "TEST-FIXTURE-PC",
        "username": "test.fixture.user",
        "logon_type": 2,
    }
    base.update(overrides)
    return base


def test_valid_event_passes_with_no_errors():
    result = validate_event(_valid_event())
    assert result.is_valid
    assert result.errors == []


def test_missing_event_id_is_a_blocking_error():
    result = validate_event(_valid_event(event_id=None))
    assert not result.is_valid
    assert "missing_event_id" in result.errors


def test_missing_computer_name_is_a_blocking_error():
    result = validate_event(_valid_event(computer_name=None))
    assert not result.is_valid
    assert "missing_computer_name" in result.errors


def test_missing_timestamp_is_a_blocking_error():
    result = validate_event(_valid_event(timestamp=None))
    assert not result.is_valid
    assert "missing_timestamp" in result.errors


def test_invalid_timestamp_is_a_blocking_error():
    result = validate_event(_valid_event(timestamp="not-a-real-timestamp"))
    assert not result.is_valid
    assert "invalid_timestamp" in result.errors


def test_missing_optional_username_is_not_an_error():
    result = validate_event(_valid_event(username=None))
    assert result.is_valid
    assert result.errors == []


def test_empty_string_username_is_a_warning_not_an_error():
    result = validate_event(_valid_event(username="   "))
    assert result.is_valid
    assert "empty_username_string" in result.warnings


def test_unexpected_logon_type_format_is_a_warning_not_an_error():
    result = validate_event(_valid_event(logon_type="not-a-number"))
    assert result.is_valid
    assert "unexpected_logon_type_format" in result.warnings


def test_parse_utc_timestamp_handles_z_suffix():
    dt = parse_utc_timestamp("2026-01-01T10:00:00.000000Z")
    assert dt is not None
    assert dt.tzinfo == timezone.utc


def test_parse_utc_timestamp_returns_none_for_garbage():
    assert parse_utc_timestamp("garbage") is None


def test_parse_utc_timestamp_returns_none_for_missing_value():
    assert parse_utc_timestamp(None) is None
