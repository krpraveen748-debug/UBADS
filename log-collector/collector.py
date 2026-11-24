"""
Windows Security Event Log collector.

Reads REAL events from the local machine's Security event log channel,
using the modern Windows Event Log API (EvtQuery / EvtNext / EvtRender) via
pywin32's `win32evtlog` module. Supports four categories (authentication,
file_activity, process_activity, device_activity) — see --categories.

Why this API rather than the classic ReadEventLog API:
  - The classic API (`win32evtlog.ReadEventLog`) returns each event's
    variable fields only as a flat, POSITIONAL list of strings
    (`StringInserts`). Mapping position -> meaning requires hardcoding the
    exact field order Windows uses for each event ID, which is fragile and
    has changed across Windows versions.
  - The modern API (`EvtQuery`/`EvtRender`) returns the event as XML with
    each field explicitly named (e.g. `TargetUserName`, `LogonType`,
    `IpAddress`), which is documented, stable, and lets us pull fields by
    name instead of guessing positions.
  - It also supports server-side XPath filtering (by EventID), so we never
    pull the entire Security log into memory — only the events we asked
    for, up to --limit.

Phase 3 extends this module with a normalize -> validate -> store pipeline
(see event_parser.py, validation.py and storage.py). This file itself still
only orchestrates: it does not contain SQL/ORM logic directly.

Phase 4 extends the categories this collector can gather (authentication,
file_activity, process_activity, device_activity), selectable via
--categories. Each requires the matching Windows audit policy to be
enabled by the machine's administrator FIRST — this script never enables
audit policy itself (see log-collector/README.md and
log-collector/scripts/ for the manual, explicit setup steps).

Phase 11 adds two things for the Windows endpoint agent (agent/), without
changing this CLI's own default behavior:
  - `collect_events(..., after_record_id=N)` queries only events whose
    EventRecordID is greater than N, oldest first — the primitive the
    agent's persistent collection cursor (agent/checkpoint.py) is built on.
  - `collect_events(..., raise_errors=True)` raises EventLogAccessDenied /
    EventLogUnavailable instead of logging and returning [], so a caller
    can report SECURITY_LOG_ACCESS_DENIED honestly rather than mistaking a
    permission problem for "zero events". With the default
    (raise_errors=False) the Phase 2-10 behavior is unchanged.

AUTHORIZATION: only run this against a Windows computer you are explicitly
authorized to collect security logs from. See log-collector/README.md.
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from event_parser import classify_download, normalize_event, parse_event_xml
from storage import PROJECT_ROOT, SessionLocal, event_record_to_dict, get_recent_events, init_db, insert_event
from validation import validate_event

try:
    import pywintypes
    import win32evtlog

    PYWIN32_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only off-Windows/without pywin32
    PYWIN32_AVAILABLE = False

# Event IDs per category. See event_parser.EVENT_CATEGORY_MAP for the
# authoritative event_id -> category mapping used during normalization;
# this is the CLI-facing inverse, used to build --event-ids from --categories.
CATEGORY_EVENT_IDS: dict[str, list[int]] = {
    "authentication": [4624, 4625, 4634, 4647],
    "file_activity": [4656, 4660, 4663],
    "process_activity": [4688],
    "device_activity": [6416],
}
DEFAULT_CATEGORIES = ["authentication"]
DEFAULT_EVENT_IDS = CATEGORY_EVENT_IDS["authentication"]
DEFAULT_LOG_NAME = "Security"

ERROR_ACCESS_DENIED = 5
ERROR_NO_MORE_ITEMS = 259

# Stable status codes reported to callers (the agent surfaces these
# verbatim) — never a silent "0 events" for a permission problem.
STATUS_OK = "OK"
STATUS_ACCESS_DENIED = "SECURITY_LOG_ACCESS_DENIED"
STATUS_LOG_UNAVAILABLE = "LOG_UNAVAILABLE"
STATUS_PYWIN32_MISSING = "PYWIN32_MISSING"

logger = logging.getLogger("log_collector")


class EventLogAccessDenied(RuntimeError):
    """The process lacks permission to read the channel (Security normally
    requires Administrator or 'Event Log Readers' membership)."""

    status = STATUS_ACCESS_DENIED


class EventLogUnavailable(RuntimeError):
    """The channel could not be opened/read for a reason other than
    permissions (e.g. it does not exist on this Windows configuration)."""

    status = STATUS_LOG_UNAVAILABLE


def _build_xpath(event_ids: list[int], after_record_id: int | None = None) -> str:
    conditions = " or ".join(f"EventID={eid}" for eid in event_ids)
    if after_record_id is not None:
        return f"*[System[({conditions}) and (EventRecordID > {int(after_record_id)})]]"
    return f"*[System[({conditions})]]"


def _open_query(log_name: str, xpath: str, reverse: bool):
    flags = win32evtlog.EvtQueryChannelPath
    if reverse:
        flags |= win32evtlog.EvtQueryReverseDirection
    try:
        return win32evtlog.EvtQuery(log_name, flags, xpath)
    except pywintypes.error as exc:
        if exc.winerror == ERROR_ACCESS_DENIED:
            raise EventLogAccessDenied(
                f"Access denied reading the '{log_name}' log. This channel usually "
                "requires Administrator privileges (or membership in the "
                "'Event Log Readers' group)."
            ) from exc
        raise EventLogUnavailable(f"Could not open Windows Event Log channel '{log_name}': {exc}") from exc


def check_log_access(log_name: str = DEFAULT_LOG_NAME) -> str:
    """Read-only probe: can this process open `log_name`? Returns one of the
    STATUS_* codes. Reads at most one event and never changes anything."""
    if not PYWIN32_AVAILABLE:
        return STATUS_PYWIN32_MISSING
    try:
        handle = _open_query(log_name, "*", reverse=True)
        win32evtlog.EvtNext(handle, 1)
    except EventLogAccessDenied:
        return STATUS_ACCESS_DENIED
    except EventLogUnavailable:
        return STATUS_LOG_UNAVAILABLE
    except pywintypes.error as exc:
        if exc.winerror == ERROR_ACCESS_DENIED:
            return STATUS_ACCESS_DENIED
        if exc.winerror != ERROR_NO_MORE_ITEMS:
            return STATUS_LOG_UNAVAILABLE
    return STATUS_OK


def get_newest_record_id(log_name: str = DEFAULT_LOG_NAME) -> int | None:
    """EventRecordID of the newest event currently in the channel (any
    event ID), or None if the channel is empty. Used by the agent to detect
    a cleared/reset log: if the newest record ID is LOWER than a saved
    cursor, record numbering has restarted and the cursor is invalid.
    Raises EventLogAccessDenied / EventLogUnavailable like collect_events."""
    if not PYWIN32_AVAILABLE:
        raise RuntimeError("pywin32 is required to read Windows Event Logs.")
    handle = _open_query(log_name, "*", reverse=True)
    try:
        events = win32evtlog.EvtNext(handle, 1)
    except pywintypes.error as exc:
        if exc.winerror == ERROR_NO_MORE_ITEMS:
            return None
        if exc.winerror == ERROR_ACCESS_DENIED:
            raise EventLogAccessDenied(str(exc)) from exc
        raise EventLogUnavailable(str(exc)) from exc
    if not events:
        return None
    parsed = parse_event_xml(win32evtlog.EvtRender(events[0], win32evtlog.EvtRenderEventXml))
    record_id = parsed.get("event_record_id")
    return record_id if isinstance(record_id, int) else None


def collect_events(
    limit: int = 20,
    event_ids: list[int] | None = None,
    log_name: str = DEFAULT_LOG_NAME,
    after_record_id: int | None = None,
    raise_errors: bool = False,
) -> list[dict]:
    """Collect up to `limit` real events matching `event_ids` from the given
    Windows Event Log channel.

    - after_record_id=None (default): the `limit` MOST RECENT matching
      events, newest first (the Phase 2-10 behavior).
    - after_record_id=N: only events with EventRecordID > N, OLDEST first,
      so a caller can page forward through the log with a cursor without
      skipping anything between cycles.

    With raise_errors=False (default) an access/availability problem is
    logged and an empty list returned, so the CLI reports it clearly
    instead of crashing. With raise_errors=True it raises
    EventLogAccessDenied / EventLogUnavailable so the caller can tell
    "access denied" apart from "no events"."""
    if not PYWIN32_AVAILABLE:
        raise RuntimeError(
            "pywin32 is required to read Windows Event Logs. "
            "Install it with: pip install pywin32"
        )

    event_ids = event_ids or DEFAULT_EVENT_IDS
    xpath = _build_xpath(event_ids, after_record_id)
    logger.info(
        "Querying Windows Event Log channel '%s' for event IDs %s (limit=%d, after_record_id=%s)",
        log_name,
        event_ids,
        limit,
        after_record_id,
    )

    try:
        query_handle = _open_query(log_name, xpath, reverse=after_record_id is None)
    except (EventLogAccessDenied, EventLogUnavailable) as exc:
        if raise_errors:
            raise
        if isinstance(exc, EventLogAccessDenied):
            logger.error(
                "Access denied reading the '%s' log. This channel usually "
                "requires Administrator privileges (or membership in the "
                "'Event Log Readers' group). See log-collector/README.md "
                "for how to run this with the required permissions.",
                log_name,
            )
        else:
            logger.error(
                "Could not open Windows Event Log channel '%s': %s "
                "(it may not exist on this Windows configuration).",
                log_name,
                exc,
            )
        return []

    collected: list[dict] = []
    while len(collected) < limit:
        batch_size = min(limit - len(collected), 10)
        try:
            events = win32evtlog.EvtNext(query_handle, batch_size)
        except pywintypes.error as exc:
            if exc.winerror == ERROR_NO_MORE_ITEMS:
                break
            if raise_errors:
                if exc.winerror == ERROR_ACCESS_DENIED:
                    raise EventLogAccessDenied(str(exc)) from exc
                raise EventLogUnavailable(str(exc)) from exc
            logger.error("Error while reading events from '%s': %s", log_name, exc)
            break

        if not events:
            break

        for event_handle in events:
            try:
                xml_str = win32evtlog.EvtRender(
                    event_handle, win32evtlog.EvtRenderEventXml
                )
                parsed = parse_event_xml(xml_str)
                normalized = normalize_event(parsed)
                normalized["_source"] = {
                    "log_name": log_name,
                    "computer_queried": "local machine",
                    "collection_method": "Windows Event Log API (EvtQuery/EvtRender)",
                }
                collected.append(normalized)
            except Exception:
                logger.exception(
                    "Failed to parse one event from '%s'; skipping it and "
                    "continuing with the rest.",
                    log_name,
                )

    logger.info("Collected %d real event(s) from '%s'.", len(collected), log_name)
    return collected


def _save_events(events: list[dict]) -> Path:
    """Write collected events to data/raw/ for manual inspection only.
    This is NOT the Phase 3 storage pipeline — just a way to keep a copy
    of what was retrieved during testing."""
    data_dir = Path(__file__).resolve().parent.parent / "data" / "raw"
    data_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = data_dir / f"windows_security_events_{timestamp}.json"
    out_path.write_text(json.dumps(events, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Collect real Windows Security event log entries (authentication, "
            "file activity, process activity, and/or device activity) from "
            "the local, authorized machine."
        )
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of recent events to retrieve (default: 20).",
    )
    parser.add_argument(
        "--categories",
        type=str,
        default=",".join(DEFAULT_CATEGORIES),
        help=(
            "Comma-separated event categories to collect: "
            f"{','.join(CATEGORY_EVENT_IDS)} (default: {','.join(DEFAULT_CATEGORIES)}). "
            "Each category's Windows audit policy must already be enabled "
            "by an administrator — see log-collector/README.md."
        ),
    )
    parser.add_argument(
        "--event-ids",
        type=str,
        default=None,
        help=(
            "Comma-separated Windows event IDs to collect. Overrides "
            "--categories entirely when given, for advanced/custom use."
        ),
    )
    parser.add_argument(
        "--log-name",
        type=str,
        default=DEFAULT_LOG_NAME,
        help="Windows Event Log channel name (default: Security).",
    )
    parser.add_argument(
        "--downloads-folder",
        type=str,
        default=None,
        help=(
            "Folder path used to classify file_activity events as "
            "'download_related' (path-based inference only — see README). "
            "Defaults to the MONITORED_DOWNLOAD_FOLDER value in config/.env."
        ),
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help=(
            "Also write the collected events as JSON under data/raw/ "
            "(temporary inspection copy only, not the SQLite pipeline)."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Collect and normalize events and print them as JSON, but do "
            "NOT validate/store them in the database (preview only)."
        ),
    )
    parser.add_argument(
        "--show",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Instead of collecting new events, print the N most recently "
            "stored events from the local SQLite database."
        ),
    )
    parser.add_argument(
        "--category",
        type=str,
        default=None,
        help="With --show, only display stored events from this category.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress INFO-level logging; print only the JSON result.",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    init_db()

    if args.show is not None:
        with SessionLocal() as session:
            records = [
                event_record_to_dict(r)
                for r in get_recent_events(session, limit=args.show, category=args.category)
            ]
        logger.info("Showing %d stored event(s) from the local database.", len(records))
        print(json.dumps(records, indent=2, ensure_ascii=False))
        return 0

    if args.event_ids:
        try:
            event_ids = [int(x.strip()) for x in args.event_ids.split(",") if x.strip()]
        except ValueError:
            logger.error("--event-ids must be a comma-separated list of integers.")
            return 1
    else:
        event_ids = []
        for category in (c.strip() for c in args.categories.split(",") if c.strip()):
            if category not in CATEGORY_EVENT_IDS:
                logger.error(
                    "Unknown category '%s'. Valid categories: %s",
                    category,
                    ", ".join(CATEGORY_EVENT_IDS),
                )
                return 1
            event_ids.extend(CATEGORY_EVENT_IDS[category])

    load_dotenv(PROJECT_ROOT / "config" / ".env")
    downloads_folder = args.downloads_folder or os.environ.get("MONITORED_DOWNLOAD_FOLDER")

    try:
        events = collect_events(limit=args.limit, event_ids=event_ids, log_name=args.log_name)
    except RuntimeError as exc:
        logger.error(str(exc))
        return 1

    if not events:
        logger.warning(
            "No events were retrieved. This can mean: no matching events "
            "exist yet on this machine, insufficient permissions, the "
            "required audit policy isn't enabled, or the log channel is "
            "unavailable — see the messages above."
        )

    for event in events:
        if event.get("event_category") == "file_activity" and classify_download(
            event.get("file_path"), downloads_folder
        ):
            event["event_category"] = "download_related"

    if args.dry_run:
        print(json.dumps(events, indent=2, ensure_ascii=False))
        if args.save and events:
            out_path = _save_events(events)
            logger.info("Saved collected events to %s", out_path)
        return 0

    inserted = 0
    duplicates = 0
    validation_failures: list[dict] = []

    with SessionLocal() as session:
        for event in events:
            result = validate_event(event)
            if not result.is_valid:
                validation_failures.append(
                    {"event_id": event.get("event_id"), "errors": result.errors}
                )
                logger.warning(
                    "Skipping invalid event (event_id=%s): %s",
                    event.get("event_id"),
                    result.errors,
                )
                continue
            if result.warnings:
                logger.info(
                    "Storing event (event_id=%s) with warnings: %s",
                    event.get("event_id"),
                    result.warnings,
                )
            outcome = insert_event(session, event, log_name=args.log_name)
            if outcome == "inserted":
                inserted += 1
            else:
                duplicates += 1

    summary = {
        "collected": len(events),
        "inserted": inserted,
        "duplicates_skipped": duplicates,
        "validation_errors": len(validation_failures),
    }
    logger.info(
        "Pipeline summary: collected=%d inserted=%d duplicates_skipped=%d validation_errors=%d",
        summary["collected"],
        summary["inserted"],
        summary["duplicates_skipped"],
        summary["validation_errors"],
    )
    print(json.dumps({"summary": summary, "validation_failures": validation_failures}, indent=2))

    if args.save and events:
        out_path = _save_events(events)
        logger.info("Saved raw normalized JSON copy to %s", out_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
