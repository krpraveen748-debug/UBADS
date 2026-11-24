"""
Tests for collector.py's category/event-ID configuration constants.

These do not touch Windows Event Log APIs (no pywin32 call is made) - they
only guard the static mapping collector.py uses to decide which Windows
event IDs a given `--categories`/agent `CATEGORIES` value queries for, so
a future edit cannot silently drop or change one of these IDs (e.g. the
authentication category losing 4624) without a test failing.
"""

from __future__ import annotations

import collector


def test_authentication_category_uses_the_four_documented_event_ids():
    """See log-collector/README.md's event-ID reference table: successful
    logon (4624), failed logon (4625), logoff (4634), user-initiated
    logoff (4647)."""
    assert collector.CATEGORY_EVENT_IDS["authentication"] == [4624, 4625, 4634, 4647]


def test_default_event_ids_are_the_authentication_category():
    assert collector.DEFAULT_EVENT_IDS == collector.CATEGORY_EVENT_IDS["authentication"]


def test_all_documented_categories_are_present():
    assert set(collector.CATEGORY_EVENT_IDS.keys()) == {
        "authentication",
        "file_activity",
        "process_activity",
        "device_activity",
    }


def test_file_process_device_categories_use_their_documented_event_ids():
    assert collector.CATEGORY_EVENT_IDS["file_activity"] == [4656, 4660, 4663]
    assert collector.CATEGORY_EVENT_IDS["process_activity"] == [4688]
    assert collector.CATEGORY_EVENT_IDS["device_activity"] == [6416]
