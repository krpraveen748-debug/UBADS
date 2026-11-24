from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import MetaData, create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import sessionmaker

from app.db.database import Base as BackendBase, _resolve_database_url
from app.models import anomaly as _anomaly_models  # noqa: F401
from app.models import dashboard_auth as _dashboard_models  # noqa: F401
from app.models import endpoint as _endpoint_models  # noqa: F401
from app.models import enrollment as _enrollment_models  # noqa: F401
from app.repositories.pipeline_bridge import storage

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = PROJECT_ROOT / "alembic.ini"
CURRENT_REVISION = "905c0c7672fc"
FRACTIONAL_COLUMNS = (
    "login_failure_ratio",
    "average_login_hour",
    "process_activity_frequency",
    "download_related_activity_frequency",
    "authentication_to_file_activity_ratio",
    "authentication_to_process_activity_ratio",
    "avg_files_per_session",
)


def _config(database_url: str, connection=None) -> Config:
    config = Config(str(ALEMBIC_INI))
    config.attributes["database_url"] = database_url
    if connection is not None:
        config.attributes["connection"] = connection
    return config


def _upgrade(database_url: str) -> None:
    command.upgrade(_config(database_url), "head")


def _sqlite_url(path: Path) -> str:
    return URL.create("sqlite", database=str(path)).render_as_string(hide_password=False)


def test_fresh_sqlite_migration_creates_both_model_schemas(tmp_path):
    database_url = _sqlite_url(tmp_path / "fresh.db")
    _upgrade(database_url)

    engine = create_engine(database_url)
    try:
        inspector = sa.inspect(engine)
        expected_tables = set(BackendBase.metadata.tables) | set(storage.Base.metadata.tables)
        assert expected_tables <= set(inspector.get_table_names())
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == CURRENT_REVISION

        feature_types = {column["name"]: column["type"] for column in inspector.get_columns("behavior_features")}
        assert all(isinstance(feature_types[name], sa.Float) for name in FRACTIONAL_COLUMNS)
        assert {index["name"] for index in inspector.get_indexes("events")} >= {
            "ix_events_event_uid",
            "ix_events_endpoint_id",
        }
    finally:
        engine.dispose()
    command.check(_config(database_url))


def test_fractional_features_round_trip_on_sqlite(tmp_path):
    database_url = _sqlite_url(tmp_path / "fractional.db")
    _upgrade(database_url)
    engine = create_engine(database_url)
    session = sessionmaker(bind=engine)()
    values = {
        "login_failure_ratio": 0.375,
        "average_login_hour": 9.5,
        "process_activity_frequency": 1.25,
        "download_related_activity_frequency": 0.125,
        "authentication_to_file_activity_ratio": 2.5,
        "authentication_to_process_activity_ratio": 0.75,
        "avg_files_per_session": 3.125,
    }
    feature = storage.BehaviorFeature(
        user_id="test-user",
        window_size="daily",
        window_start=datetime(2026, 11, 1, tzinfo=timezone.utc),
        window_end=datetime(2026, 11, 2, tzinfo=timezone.utc),
        total_activity_count=4,
        number_of_categories_active=2,
        day_of_week=6,
        is_weekend=1,
        off_hours_activity_count=1,
        distinct_active_hours=3,
        computed_at=datetime.now(timezone.utc),
        **values,
    )
    try:
        session.add(feature)
        session.commit()
        stored = session.query(storage.BehaviorFeature).one()
        assert {name: getattr(stored, name) for name in FRACTIONAL_COLUMNS} == values
    finally:
        session.close()
        engine.dispose()


def test_legacy_sqlite_upgrade_preserves_data_and_converts_fractional_columns(tmp_path):
    database_url = _sqlite_url(tmp_path / "legacy.db")
    engine = create_engine(database_url)
    legacy_metadata = MetaData()
    for metadata in (BackendBase.metadata, storage.Base.metadata):
        for table in metadata.sorted_tables:
            legacy_table = table.to_metadata(legacy_metadata)
            if table.name == "behavior_features":
                for name in FRACTIONAL_COLUMNS:
                    legacy_table.c[name].type = sa.Integer()
    legacy_metadata.create_all(engine)

    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO dashboard_users (username, password_hash, created_at, role) "
                "VALUES ('fixture-admin', 'scrypt$fixture', '2026-01-01 00:00:00', 'admin')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO dashboard_sessions (token_hash, username, created_at, expires_at) "
                "VALUES ('token-hash-fixture', 'fixture-admin', '2026-01-01 00:00:00', '2027-01-01 00:00:00')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO endpoints (endpoint_id, status, registered_at, credential_hash) "
                "VALUES ('fixture-endpoint', 'active', '2026-01-01 00:00:00', 'sha256:fixture')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO endpoint_requests "
                "(id, username, organization, requested_scope, consent_version, consent_acknowledged_at, "
                "status, created_at, updated_at) "
                "VALUES ('fixture-request', 'fixture-admin', 'Fixture Org', 'authentication', 'test-v1', "
                "'2026-01-01 00:00:00', 'INSTALLED', '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO events "
                "(event_uid, event_id, event_type, timestamp_utc, computer_name, endpoint_id, collection_timestamp) "
                "VALUES ('fixture-event-uid', 4624, 'successful_logon', '2026-01-01 00:00:00', "
                "'FIXTURE-PC', 'fixture-endpoint', '2026-01-01 00:00:00')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO behavior_features "
                "(user_id, window_size, window_start, window_end, total_activity_count, "
                "number_of_categories_active, day_of_week, is_weekend, off_hours_activity_count, "
                "distinct_active_hours, average_login_hour, computed_at) "
                "VALUES ('fixture-user', 'daily', '2026-01-01 00:00:00', '2026-01-02 00:00:00', "
                "4, 2, 3, 0, 1, 2, 9.5, '2026-01-02 00:00:00')"
            )
        )

    engine.dispose()
    _upgrade(database_url)

    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            assert connection.scalar(
                text("SELECT credential_hash FROM endpoints WHERE endpoint_id='fixture-endpoint'")
            ) == "sha256:fixture"
            assert connection.scalar(
                text("SELECT endpoint_id FROM events WHERE event_uid='fixture-event-uid'")
            ) == "fixture-endpoint"
            assert connection.scalar(
                text("SELECT status FROM endpoint_requests WHERE id='fixture-request'")
            ) == "ENROLLED"
            assert connection.scalar(
                text("SELECT username FROM dashboard_sessions WHERE token_hash='token-hash-fixture'")
            ) == "fixture-admin"
            assert connection.scalar(
                text("SELECT average_login_hour FROM behavior_features WHERE user_id='fixture-user'")
            ) == pytest.approx(9.5)
        feature_type = {
            column["name"]: column["type"]
            for column in sa.inspect(engine).get_columns("behavior_features")
        }["average_login_hour"]
        assert isinstance(feature_type, sa.Float)
    finally:
        engine.dispose()


def test_unversioned_sqlite_schema_gets_legacy_columns_without_losing_rows(tmp_path):
    database_url = _sqlite_url(tmp_path / "unversioned.db")
    engine = create_engine(database_url)
    BackendBase.metadata.create_all(engine)
    storage.Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP INDEX ix_events_event_category")
        connection.exec_driver_sql("DROP INDEX ix_events_endpoint_id")
        connection.exec_driver_sql("ALTER TABLE events DROP COLUMN event_category")
        connection.exec_driver_sql("ALTER TABLE events DROP COLUMN endpoint_id")
        for column in (
            "credential_hash",
            "credential_issued_at",
            "last_ingest_at",
            "monitoring_scope",
            "enrolled_request_id",
        ):
            connection.exec_driver_sql(f"ALTER TABLE endpoints DROP COLUMN {column}")
        for column in ("role", "email", "full_name", "organization"):
            connection.exec_driver_sql(f"ALTER TABLE dashboard_users DROP COLUMN {column}")
        connection.exec_driver_sql("ALTER TABLE enrollment_authorizations DROP COLUMN revoked_at")
        connection.exec_driver_sql("ALTER TABLE enrollment_authorizations DROP COLUMN redeemed_from_ip")
        connection.execute(
            text(
                "INSERT INTO dashboard_users (username, password_hash, created_at) "
                "VALUES ('legacy-admin', 'scrypt$fixture', '2026-01-01 00:00:00')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO endpoints "
                "(endpoint_id, status, registered_at) "
                "VALUES ('legacy-endpoint', 'active', '2026-01-01 00:00:00')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO events "
                "(event_uid, event_id, event_type, timestamp_utc, computer_name, collection_timestamp) "
                "VALUES ('legacy-event', 4624, 'successful_logon', '2026-01-01 00:00:00', "
                "'FIXTURE-PC', '2026-01-01 00:00:00')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO endpoint_requests "
                "(id, username, organization, requested_scope, consent_version, consent_acknowledged_at, "
                "status, created_at, updated_at) "
                "VALUES ('legacy-request', 'legacy-admin', 'Fixture Org', 'authentication', 'test-v1', "
                "'2026-01-01 00:00:00', 'INSTALLED', '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
            )
        )
    engine.dispose()

    _upgrade(database_url)

    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            assert tuple(
                connection.execute(
                    text("SELECT username, role, email FROM dashboard_users WHERE username='legacy-admin'")
                ).one()
            ) == ("legacy-admin", "admin", None)
            assert tuple(
                connection.execute(
                    text("SELECT event_category, endpoint_id FROM events WHERE event_uid='legacy-event'")
                ).one()
            ) == ("authentication", None)
            assert connection.scalar(
                text("SELECT status FROM endpoint_requests WHERE id='legacy-request'")
            ) == "ENROLLED"
            endpoint_columns = {column["name"] for column in sa.inspect(engine).get_columns("endpoints")}
            enrollment_columns = {
                column["name"] for column in sa.inspect(engine).get_columns("enrollment_authorizations")
            }
            assert {"monitoring_scope", "enrolled_request_id", "credential_hash"} <= endpoint_columns
            assert {"revoked_at", "redeemed_from_ip"} <= enrollment_columns
    finally:
        engine.dispose()


def test_database_urls_normalize_to_one_sqlite_path_and_psycopg_driver(monkeypatch):
    relative_url = "sqlite:///./data/app.db"
    monkeypatch.setenv("DATABASE_URL", relative_url)
    backend_url = _resolve_database_url(relative_url)
    event_url = make_url(storage._resolve_database_url())
    assert backend_url.database == event_url.database
    assert Path(backend_url.database).is_absolute()

    postgres_url = _resolve_database_url("postgresql://test:test@db.example/ubads_test")
    assert postgres_url.drivername == "postgresql+psycopg"


def test_storage_init_db_requires_migrations_without_changing_schema(monkeypatch):
    engine = create_engine("sqlite://")
    monkeypatch.setattr(storage, "engine", engine)
    try:
        with pytest.raises(RuntimeError, match="alembic upgrade head"):
            storage.init_db()
        assert sa.inspect(engine).get_table_names() == []
    finally:
        engine.dispose()


def test_postgresql_migration_in_isolated_schema_when_configured():
    configured_url = os.environ.get("UBADS_TEST_POSTGRES_URL")
    if not configured_url:
        pytest.skip("UBADS_TEST_POSTGRES_URL is not configured.")
    url = make_url(configured_url)
    assert url.get_backend_name() == "postgresql"
    if not url.database or not url.database.lower().endswith(("_test", "testing")):
        pytest.fail("UBADS_TEST_POSTGRES_URL must target a database whose name ends with _test or testing.")

    schema = f"ubads_test_{uuid.uuid4().hex}"
    engine = create_engine(url)
    created = False
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
            created = True
        with engine.connect() as connection:
            connection.exec_driver_sql(f'SET search_path TO "{schema}"')
            command.upgrade(_config(configured_url, connection), "head")
            inspector = sa.inspect(connection)
            expected_tables = set(BackendBase.metadata.tables) | set(storage.Base.metadata.tables)
            assert expected_tables <= set(inspector.get_table_names())
            types = {column["name"]: column["type"] for column in inspector.get_columns("behavior_features")}
            assert all(isinstance(types[name], sa.Float) for name in FRACTIONAL_COLUMNS)
            session = sessionmaker(bind=connection)()
            try:
                session.add(
                    storage.BehaviorFeature(
                        user_id="pg-fixture-user",
                        window_size="daily",
                        window_start=datetime(2026, 11, 1, tzinfo=timezone.utc),
                        window_end=datetime(2026, 11, 2, tzinfo=timezone.utc),
                        total_activity_count=1,
                        number_of_categories_active=1,
                        day_of_week=6,
                        is_weekend=1,
                        off_hours_activity_count=0,
                        distinct_active_hours=1,
                        average_login_hour=9.5,
                        computed_at=datetime.now(timezone.utc),
                    )
                )
                session.commit()
                assert session.query(storage.BehaviorFeature.average_login_hour).scalar() == pytest.approx(9.5)
            finally:
                session.close()
    finally:
        if created:
            with engine.begin() as connection:
                connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
        engine.dispose()
