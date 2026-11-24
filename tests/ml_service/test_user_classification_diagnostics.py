"""
Tests for user_classification_diagnostics.py. Event dicts below are
CLASSIFICATION-DIAGNOSTIC TEST FIXTURES ONLY — hand-written, not real
project data. They must never be confused with, or counted alongside, the
real rows in data/app.db.
"""

from user_classification_diagnostics import generate_user_classification_report


def _event(username, domain, user_sid, category="authentication"):
    return {
        "username": username,
        "domain": domain,
        "user_sid": user_sid,
        "event_category": category,
    }


def test_service_account_is_excluded_with_reason():
    events = [_event("SYSTEM", "NT AUTHORITY", "S-1-5-18")]
    report = generate_user_classification_report(events)
    account = report["accounts"][0]
    assert account["account_type"] == "system"
    assert account["is_human_candidate"] is False
    assert "SYSTEM" in account["exclusion_reason"]


def test_normal_authorized_windows_account_is_human_candidate():
    events = [
        _event(
            "test.fixture.human.user",
            "FIXTURE-DOMAIN",
            "S-1-5-21-1111111111-2222222222-3333333333-1001",
        )
    ]
    report = generate_user_classification_report(events)
    account = report["accounts"][0]
    assert account["account_type"] == "human_or_unknown"
    assert account["is_human_candidate"] is True
    assert account["exclusion_reason"] is None


def test_missing_username_is_unknown_and_excluded():
    events = [_event(None, None, None, category=None)]
    report = generate_user_classification_report(events)
    account = report["accounts"][0]
    assert account["account_type"] == "unknown"
    assert account["is_human_candidate"] is False
    assert account["exclusion_reason"] is not None


def test_virtual_service_accounts_excluded():
    events = [_event("DWM-2", "Window Manager", "S-1-5-90-0-2")]
    report = generate_user_classification_report(events)
    account = report["accounts"][0]
    assert account["account_type"] == "virtual_service_account"
    assert account["is_human_candidate"] is False


def test_conservative_fallback_for_unrecognized_but_present_username():
    # An account_type this diagnostic has never seen before shouldn't crash
    # the reason lookup — it should fall back to a generic explanation.
    events = [_event("someone.new", "SOME-DOMAIN", "S-1-5-21-1-2-3-9999")]
    report = generate_user_classification_report(events)
    account = report["accounts"][0]
    assert account["account_type"] == "human_or_unknown"
    assert account["is_human_candidate"] is True


def test_report_does_not_expose_raw_sid_value():
    events = [_event("alice", "CORP", "S-1-5-21-1-2-3-1001")]
    report = generate_user_classification_report(events)
    account = report["accounts"][0]
    assert "user_sid" not in account
    assert account["sid_present"] is True


def test_categorized_vs_uncategorized_counts():
    events = [
        _event("alice", "CORP", "S-1-5-21-1-2-3-1001", category="authentication"),
        _event("alice", "CORP", "S-1-5-21-1-2-3-1001", category="uncategorized"),
        _event("alice", "CORP", "S-1-5-21-1-2-3-1001", category=None),
    ]
    report = generate_user_classification_report(events)
    assert report["categorized_vs_uncategorized"] == {"categorized": 1, "uncategorized": 2}


def test_human_candidate_account_count_aggregate():
    events = [
        _event("SYSTEM", "NT AUTHORITY", "S-1-5-18"),
        _event("alice", "CORP", "S-1-5-21-1-2-3-1001"),
        _event("bob", "CORP", "S-1-5-21-1-2-3-1002"),
    ]
    report = generate_user_classification_report(events)
    assert report["human_candidate_account_count"] == 2
    assert report["total_distinct_accounts"] == 3
