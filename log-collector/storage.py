"""
Repository / database layer for normalized events.

Pipeline this module sits in:

    Windows Collector (collector.py)
          -> Normalizer (event_parser.py)
          -> Validation (validation.py)
          -> Repository (this module)
          -> SQLite (data/app.db)

Why a separate module: collector.py should orchestrate collection, not
contain SQL/ORM logic. Isolating storage here lets the collector, backend,
and feature tools use a shared configured database without changing the
event normalization or validation pipeline.

Database location: this module and the FastAPI backend
(backend/app/db/database.py) intentionally read the SAME `DATABASE_URL`
environment variable from the same `config/.env` file, so both point at the
same local SQLite file (data/app.db) without importing each other's code.
They stay independent on purpose — `log-collector/` is a hyphenated
directory name (not a valid Python package name) and Phase 2 deliberately
kept it free of any dependency on the `backend` package. Agreeing on one
environment variable is enough to keep them in sync.

Phase 4 — one generalized table, not one table per category: all
categories (authentication, file_activity, process_activity,
device_activity, download_related) share the same `events` table, with
category-specific columns simply left NULL when not applicable. This was
chosen over separate per-category tables because:
  - Every category already shares most columns (timestamp, computer,
    username/domain/sid, account_type, raw_event_data, dedup key).
  - Phase 5 (feature engineering) will need to correlate *across*
    categories for one user/machine/time-window (e.g. "logon, then file
    access, then process launch") — one table makes that a single
    `WHERE`/`ORDER BY` query instead of N-way joins across separate tables.
  - Schema stays simple: one dedup strategy, one insert path, one place to
    add a future category's columns, rather than duplicating that
    machinery per table.
The tradeoff (some NULL columns per row depending on category) is judged
acceptable for a single-machine research/development database at this
scale.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import Column, DateTime, Float, Integer, String, Text, UniqueConstraint, create_engine, inspect
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from event_sanitizer import sanitize_event_for_storage
from validation import parse_utc_timestamp

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SQLITE_PATH = PROJECT_ROOT / "data" / "app.db"


def _resolve_database_url() -> str:
    """Read DATABASE_URL from config/.env (same variable the backend uses).
    Relative sqlite:///./... paths are resolved against the project root
    (not the current working directory), so the collector writes to the
    same file whether it's run from the project root or from inside
    log-collector/."""
    load_dotenv(PROJECT_ROOT / "config" / ".env")
    url = os.environ.get("DATABASE_URL")
    if not url:
        url = f"sqlite:///{DEFAULT_SQLITE_PATH.as_posix()}"
    parsed = make_url(url)
    if parsed.drivername in {"postgres", "postgresql"}:
        parsed = parsed.set(drivername="postgresql+psycopg")
    elif parsed.drivername == "sqlite" and parsed.database not in (None, "", ":memory:"):
        path = Path(parsed.database)
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        parsed = parsed.set(database=str(path.resolve()))
    return parsed.render_as_string(hide_password=False)


DATABASE_URL = _resolve_database_url()

_database_url = make_url(DATABASE_URL)
if _database_url.get_backend_name() == "sqlite":
    _engine_options = {
        "connect_args": {"check_same_thread": False, "timeout": 30},
        "pool_pre_ping": True,
    }
else:
    _engine_options = {
        "connect_args": {"connect_timeout": 10},
        "pool_pre_ping": True,
        "pool_size": 5,
        "max_overflow": 5,
        "pool_timeout": 30,
        "pool_recycle": 1800,
    }
engine = create_engine(DATABASE_URL, **_engine_options)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


class EventRecord(Base):
    """Normalized, validated event, ready for future feature engineering.

    Column choices map to the Phase 2 normalized event fields:
      - `source_machine` stores Windows' WorkstationName field — the
        machine the logon *originated from* (relevant for network logons),
        distinct from `computer_name`, which is the machine that recorded
        the event (i.e. this local computer).
      - `raw_event_data` preserves every named field Windows provided for
        the event, as JSON, so nothing is lost even if a future phase needs
        a field this schema doesn't surface as its own column. For the
        event IDs this project collects (4624/4625/4634/4647), Microsoft's
        documented schema does not include credentials of any kind, so
        retaining this is safe (see log-collector/README.md, Privacy).
    """

    __tablename__ = "events"
    __table_args__ = (UniqueConstraint("event_uid", name="uq_events_event_uid"),)

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Deduplication key — see build_event_uid().
    event_uid = Column(String, nullable=False, index=True)

    event_id = Column(Integer, nullable=False)
    event_record_id = Column(String, nullable=True)
    event_type = Column(String, nullable=False)
    # authentication / file_activity / process_activity / device_activity /
    # download_related / uncategorized — see event_parser.EVENT_CATEGORY_MAP.
    # download_related is applied on top of file_activity events whose path
    # falls under a configured downloads folder (see event_parser.classify_download).
    event_category = Column(String, nullable=True, index=True)

    # Original Windows event time, normalized to UTC, plus the untouched
    # raw string it came from (see validation.parse_utc_timestamp).
    timestamp_utc = Column(DateTime(timezone=True), nullable=False)
    timestamp_raw = Column(String, nullable=True)

    computer_name = Column(String, nullable=False)
    log_name = Column(String, nullable=True)

    # Phase 11: the AUTHENTICATED endpoint that submitted this event via
    # POST /api/ingest/events (taken from the agent's verified credential,
    # never from the request body). NULL for events stored locally by
    # log-collector/collector.py or ingested before Phase 11.
    endpoint_id = Column(String, nullable=True, index=True)

    username = Column(String, nullable=True)
    domain = Column(String, nullable=True)
    user_sid = Column(String, nullable=True)
    account_type = Column(String, nullable=True)

    # -- authentication-specific --
    logon_type = Column(Integer, nullable=True)
    logon_type_description = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)
    source_machine = Column(String, nullable=True)
    subject_username = Column(String, nullable=True)
    subject_domain = Column(String, nullable=True)
    failure_reason = Column(String, nullable=True)

    # -- file_activity-specific (also used by download_related) --
    file_path = Column(String, nullable=True)
    file_extension = Column(String, nullable=True)
    object_type = Column(String, nullable=True)
    file_action = Column(String, nullable=True)
    process_name = Column(String, nullable=True)
    access_list_raw = Column(Text, nullable=True)

    # -- process_activity-specific --
    process_id = Column(String, nullable=True)
    parent_process_id = Column(String, nullable=True)
    parent_process_name = Column(String, nullable=True)

    # -- device_activity-specific --
    device_id = Column(String, nullable=True)
    device_description = Column(String, nullable=True)
    device_class = Column(String, nullable=True)
    device_action = Column(String, nullable=True)

    raw_event_data = Column(Text, nullable=True)

    # When OUR pipeline processed/stored this record — distinct from the
    # event's own timestamp_utc.
    collection_timestamp = Column(DateTime(timezone=True), nullable=False)


def init_db() -> None:
    """Require a schema created by the controlled Alembic migration command."""
    if "alembic_version" not in inspect(engine).get_table_names():
        raise RuntimeError("Database schema is not migrated. Run `alembic upgrade head` before starting.")


def build_event_uid(
    computer_name: str | None,
    log_name: str | None,
    event_record_id: int | str | None,
    event_id: int | None,
    timestamp: str | None,
    endpoint_id: str | None = None,
) -> str:
    """Deduplication key.

    Preferred: Windows' own EventRecordID is a sequential, unique-per-log-
    channel-per-computer identifier — the most reliable natural key
    available, so (computer_name, log_name, event_record_id) uniquely
    identifies one real event.

    Fallback (only if EventRecordID was somehow unavailable): computer +
    log + event_id + timestamp. This is not perfectly guaranteed unique
    (two distinct events could in theory share a timestamp) but is the best
    available combination, and is documented here as a known limitation
    rather than silently assumed to be perfect.

    Known edge case: if the Windows log is cleared, EventRecordID numbering
    restarts from 1, which could in theory collide with a previously seen
    ID on the same computer/log. This is rare and acceptable for a local
    research/development tool; it is not attempted to be solved here.

    Phase 11: when `endpoint_id` is given (events ingested from an
    authenticated agent), the key is prefixed with it. `computer_name` is
    agent-REPORTED data, so without this prefix one enrolled endpoint could
    submit events claiming another machine's computer_name/record IDs and
    make that machine's real events be rejected as "duplicates". Keys
    without an endpoint_id keep the exact Phase 3 format.
    """
    if event_record_id is not None:
        key = f"{computer_name}|{log_name}|{event_record_id}"
    else:
        key = f"{computer_name}|{log_name}|fallback|{event_id}|{timestamp}"
    if endpoint_id:
        return f"ep:{endpoint_id}|{key}"
    return key


def insert_event(
    session: Session, normalized_event: dict, log_name: str, endpoint_id: str | None = None
) -> str:
    """Insert one already-validated, normalized event.

    Returns "inserted" or "duplicate". Assumes the caller already ran
    validation.validate_event() and confirmed is_valid=True (so timestamp
    and event_id are known-good).

    `endpoint_id` (Phase 11) is supplied ONLY by the backend's ingestion
    service, from the authenticated agent credential — any "endpoint_id"
    key inside `normalized_event` itself is ignored.
    """
    # Last line of defence: whatever client produced this event, never persist command lines or
    # other non-allowlisted raw fields, and mask secret-looking free text (event_sanitizer.py).
    normalized_event = sanitize_event_for_storage(normalized_event)
    key_args = (
        normalized_event.get("computer_name"),
        log_name,
        normalized_event.get("event_record_id"),
        normalized_event.get("event_id"),
        normalized_event.get("timestamp"),
    )
    event_uid = build_event_uid(*key_args, endpoint_id=endpoint_id)

    existing = session.query(EventRecord).filter_by(event_uid=event_uid).first()
    if existing is None and endpoint_id:
        # The same real event may already be stored from before Phase 11
        # (legacy un-prefixed key, no endpoint attribution). Treat that as a
        # duplicate rather than storing the event twice.
        existing = (
            session.query(EventRecord)
            .filter(EventRecord.event_uid == build_event_uid(*key_args), EventRecord.endpoint_id.is_(None))
            .first()
        )
    if existing is not None:
        return "duplicate"

    timestamp_utc = parse_utc_timestamp(normalized_event.get("timestamp"))
    logon_type = normalized_event.get("logon_type")

    record = EventRecord(
        event_uid=event_uid,
        event_id=normalized_event["event_id"],
        event_record_id=(
            str(normalized_event["event_record_id"])
            if normalized_event.get("event_record_id") is not None
            else None
        ),
        event_type=normalized_event.get("event_type"),
        event_category=normalized_event.get("event_category"),
        timestamp_utc=timestamp_utc,
        timestamp_raw=normalized_event.get("timestamp"),
        computer_name=normalized_event.get("computer_name"),
        log_name=log_name,
        endpoint_id=endpoint_id,
        username=normalized_event.get("username"),
        domain=normalized_event.get("domain"),
        user_sid=normalized_event.get("user_sid"),
        account_type=normalized_event.get("account_type"),
        logon_type=logon_type if isinstance(logon_type, int) else None,
        logon_type_description=normalized_event.get("logon_type_description"),
        source_ip=normalized_event.get("source_ip"),
        source_machine=normalized_event.get("workstation_name"),
        subject_username=normalized_event.get("subject_username"),
        subject_domain=normalized_event.get("subject_domain"),
        failure_reason=normalized_event.get("failure_reason"),
        file_path=normalized_event.get("file_path"),
        file_extension=normalized_event.get("file_extension"),
        object_type=normalized_event.get("object_type"),
        file_action=normalized_event.get("file_action"),
        process_name=normalized_event.get("process_name"),
        access_list_raw=normalized_event.get("access_list_raw"),
        process_id=normalized_event.get("process_id"),
        parent_process_id=normalized_event.get("parent_process_id"),
        parent_process_name=normalized_event.get("parent_process_name"),
        device_id=normalized_event.get("device_id"),
        device_description=normalized_event.get("device_description"),
        device_class=normalized_event.get("device_class"),
        device_action=normalized_event.get("device_action"),
        raw_event_data=json.dumps(normalized_event.get("raw_event_data", {}), ensure_ascii=False),
        collection_timestamp=datetime.now(timezone.utc),
    )
    session.add(record)
    session.commit()
    return "inserted"


def get_recent_events(
    session: Session, limit: int = 20, category: str | None = None
) -> list[EventRecord]:
    query = session.query(EventRecord)
    if category:
        query = query.filter(EventRecord.event_category == category)
    return query.order_by(EventRecord.timestamp_utc.desc()).limit(limit).all()


def get_all_events(session: Session, endpoint_id: str | None = None) -> list[EventRecord]:
    """All stored events, oldest first. Phase 5 (ml-service/feature_engineering.py)
    reads the whole history this way rather than via SQL aggregation — a
    deliberate simplification appropriate for a single-machine research
    dataset at this scale (see ml-service/README.md)."""
    query = session.query(EventRecord)
    if endpoint_id is not None:
        query = query.filter(EventRecord.endpoint_id == endpoint_id)
    return query.order_by(EventRecord.timestamp_utc.asc()).all()


def query_events(
    session: Session,
    *,
    limit: int = 50,
    offset: int = 0,
    category: str | None = None,
    username: str | None = None,
    event_id: int | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    endpoint_id: str | None = None,
) -> tuple[list[EventRecord], int]:
    """Filtered, paginated event query — added for Phase 8B (backend API).
    Returns (page_of_rows, total_matching_count). Newest first. Only
    filters actually requested are applied; an unset filter matches
    everything, never a guessed default.

    `endpoint_id` (Phase 14) lets a caller — the frontend's Events page,
    in particular — scope results to ONE enrolled endpoint, so the
    dashboard can show multiple endpoints' events without mixing them
    together. Rows from before Phase 11 (or collected by the local
    `log-collector/collector.py` CLI directly, never through the agent)
    have `endpoint_id IS NULL` and are excluded whenever a specific
    endpoint_id is requested — never silently included as if they
    belonged to that endpoint."""
    query = session.query(EventRecord)
    if category:
        query = query.filter(EventRecord.event_category == category)
    if username:
        query = query.filter(EventRecord.username == username)
    if event_id is not None:
        query = query.filter(EventRecord.event_id == event_id)
    if start_time is not None:
        query = query.filter(EventRecord.timestamp_utc >= start_time)
    if end_time is not None:
        query = query.filter(EventRecord.timestamp_utc <= end_time)
    if endpoint_id:
        query = query.filter(EventRecord.endpoint_id == endpoint_id)

    total = query.count()
    rows = query.order_by(EventRecord.timestamp_utc.desc()).offset(offset).limit(limit).all()
    return rows, total


def get_event_by_id(session: Session, record_id: int) -> EventRecord | None:
    """Look up one event by its database primary key (`id`) — NOT the raw
    Windows `event_id` (e.g. 4624), which is not unique across rows.
    Added for Phase 8B (GET /api/events/{id})."""
    return session.get(EventRecord, record_id)


def event_record_to_dict(record: EventRecord) -> dict:
    return {
        "id": record.id,
        "event_uid": record.event_uid,
        "event_id": record.event_id,
        "event_record_id": record.event_record_id,
        "event_type": record.event_type,
        "event_category": record.event_category,
        "timestamp_utc": record.timestamp_utc.isoformat() if record.timestamp_utc else None,
        "timestamp_raw": record.timestamp_raw,
        "computer_name": record.computer_name,
        "log_name": record.log_name,
        "endpoint_id": record.endpoint_id,
        "username": record.username,
        "domain": record.domain,
        "user_sid": record.user_sid,
        "account_type": record.account_type,
        "logon_type": record.logon_type,
        "logon_type_description": record.logon_type_description,
        "source_ip": record.source_ip,
        "source_machine": record.source_machine,
        "subject_username": record.subject_username,
        "subject_domain": record.subject_domain,
        "failure_reason": record.failure_reason,
        "file_path": record.file_path,
        "file_extension": record.file_extension,
        "object_type": record.object_type,
        "file_action": record.file_action,
        "process_name": record.process_name,
        "access_list_raw": record.access_list_raw,
        "process_id": record.process_id,
        "parent_process_id": record.parent_process_id,
        "parent_process_name": record.parent_process_name,
        "device_id": record.device_id,
        "device_description": record.device_description,
        "device_class": record.device_class,
        "device_action": record.device_action,
        "collection_timestamp": (
            record.collection_timestamp.isoformat() if record.collection_timestamp else None
        ),
        "raw_event_data": json.loads(record.raw_event_data) if record.raw_event_data else {},
    }


# ---------------------------------------------------------------------------
# Phase 5 — behavior_features table
#
# Same database, same Base/engine as `events` — per Phase 4's design choice,
# this project uses one SQLite file for everything rather than a second,
# unrelated database. See ml-service/README.md and ml-service/FEATURES.md
# for what each column means and how it's calculated; this module only
# defines the schema and persistence (insert/upsert/read), not the feature
# math itself (that lives in ml-service/features.py, which is pure/testable
# without a database).
# ---------------------------------------------------------------------------


class BehaviorFeature(Base):
    """One row = one (user, time window) behavioral feature vector, computed
    entirely from real stored events — see ml-service/feature_engineering.py.

    Nullable columns follow one rule throughout: `None` means either "this
    category was never observed anywhere in the database" (the category's
    audit policy was likely never enabled) or "this ratio/stat is undefined
    for this window" (e.g. division by zero) — NEVER "we assumed zero
    activity". A real, counted zero (the category IS observed elsewhere in
    the dataset, just not in this particular window) is stored as the
    integer 0. See ml-service/FEATURES.md for the exact rule per feature.
    """

    __tablename__ = "behavior_features"
    __table_args__ = (
        UniqueConstraint("user_id", "window_start", "window_size", name="uq_behavior_features_window"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)

    user_id = Column(String, nullable=False, index=True)
    username = Column(String, nullable=True)
    domain = Column(String, nullable=True)
    account_type = Column(String, nullable=True)

    window_size = Column(String, nullable=False)  # "hourly" | "daily"
    window_start = Column(DateTime(timezone=True), nullable=False, index=True)
    window_end = Column(DateTime(timezone=True), nullable=False)

    # -- always computable (don't depend on any one category) --
    total_activity_count = Column(Integer, nullable=False)
    number_of_categories_active = Column(Integer, nullable=False)
    day_of_week = Column(Integer, nullable=False)
    is_weekend = Column(Integer, nullable=False)
    off_hours_activity_count = Column(Integer, nullable=False)
    distinct_active_hours = Column(Integer, nullable=False)

    # -- authentication (None if authentication category never observed at all) --
    successful_login_count = Column(Integer, nullable=True)
    failed_login_count = Column(Integer, nullable=True)
    login_failure_ratio = Column(Float, nullable=True)
    unique_login_hours = Column(Integer, nullable=True)
    first_login_hour = Column(Integer, nullable=True)
    last_login_hour = Column(Integer, nullable=True)
    average_login_hour = Column(Float, nullable=True)
    logoff_count = Column(Integer, nullable=True)

    # -- file_activity (None if file_activity category never observed at all) --
    files_accessed = Column(Integer, nullable=True)
    files_deleted = Column(Integer, nullable=True)
    files_handle_requested = Column(Integer, nullable=True)
    unique_file_extensions = Column(Integer, nullable=True)
    unique_directories = Column(Integer, nullable=True)
    file_activity_count = Column(Integer, nullable=True)

    # -- process_activity (None if process_activity category never observed at all) --
    process_count = Column(Integer, nullable=True)
    unique_process_count = Column(Integer, nullable=True)
    process_activity_frequency = Column(Float, nullable=True)

    # -- device_activity (None if device_activity category never observed at all) --
    device_event_count = Column(Integer, nullable=True)
    unique_devices = Column(Integer, nullable=True)
    new_device_count = Column(Integer, nullable=True)

    # -- download_related (None if never observed at all) --
    download_related_event_count = Column(Integer, nullable=True)
    download_related_file_count = Column(Integer, nullable=True)
    download_related_activity_frequency = Column(Float, nullable=True)

    # -- cross-category (None if a required category is unavailable, or undefined e.g. 0/0) --
    authentication_to_file_activity_ratio = Column(Float, nullable=True)
    authentication_to_process_activity_ratio = Column(Float, nullable=True)
    activity_after_failed_login_count = Column(Integer, nullable=True)
    avg_files_per_session = Column(Float, nullable=True)

    computed_at = Column(DateTime(timezone=True), nullable=False)


_FEATURE_NUMERIC_COLUMNS: list[str] = [
    "total_activity_count",
    "number_of_categories_active",
    "day_of_week",
    "is_weekend",
    "off_hours_activity_count",
    "distinct_active_hours",
    "successful_login_count",
    "failed_login_count",
    "login_failure_ratio",
    "unique_login_hours",
    "first_login_hour",
    "last_login_hour",
    "average_login_hour",
    "logoff_count",
    "files_accessed",
    "files_deleted",
    "files_handle_requested",
    "unique_file_extensions",
    "unique_directories",
    "file_activity_count",
    "process_count",
    "unique_process_count",
    "process_activity_frequency",
    "device_event_count",
    "unique_devices",
    "new_device_count",
    "download_related_event_count",
    "download_related_file_count",
    "download_related_activity_frequency",
    "authentication_to_file_activity_ratio",
    "authentication_to_process_activity_ratio",
    "activity_after_failed_login_count",
    "avg_files_per_session",
]


def save_feature_record(session: Session, record: dict) -> str:
    """Upsert one behavior_features row, keyed by (user_id, window_start,
    window_size). Unlike events (append-only, deduped by real event
    identity), feature rows are RECOMPUTED values derived from whatever
    events exist at run time — if you collect more events for a window
    that was already processed and re-run feature engineering, the row is
    intentionally updated in place rather than duplicated."""
    existing = (
        session.query(BehaviorFeature)
        .filter_by(
            user_id=record["user_id"],
            window_start=record["window_start"],
            window_size=record["window_size"],
        )
        .first()
    )

    now = datetime.now(timezone.utc)
    if existing is not None:
        for key in _FEATURE_NUMERIC_COLUMNS + ["username", "domain", "account_type", "window_end"]:
            setattr(existing, key, record.get(key))
        existing.computed_at = now
        session.commit()
        return "updated"

    feature_record = BehaviorFeature(
        user_id=record["user_id"],
        username=record.get("username"),
        domain=record.get("domain"),
        account_type=record.get("account_type"),
        window_size=record["window_size"],
        window_start=record["window_start"],
        window_end=record["window_end"],
        computed_at=now,
        **{key: record.get(key) for key in _FEATURE_NUMERIC_COLUMNS},
    )
    session.add(feature_record)
    session.commit()
    return "inserted"


def get_feature_records(
    session: Session, user_id: str | None = None, limit: int = 100
) -> list[BehaviorFeature]:
    query = session.query(BehaviorFeature)
    if user_id:
        query = query.filter(BehaviorFeature.user_id == user_id)
    return query.order_by(BehaviorFeature.window_start.desc()).limit(limit).all()


def feature_record_to_dict(record: BehaviorFeature) -> dict:
    result = {
        "id": record.id,
        "user_id": record.user_id,
        "username": record.username,
        "domain": record.domain,
        "account_type": record.account_type,
        "window_size": record.window_size,
        "window_start": record.window_start.isoformat() if record.window_start else None,
        "window_end": record.window_end.isoformat() if record.window_end else None,
        "computed_at": record.computed_at.isoformat() if record.computed_at else None,
    }
    for key in _FEATURE_NUMERIC_COLUMNS:
        result[key] = getattr(record, key)
    return result
