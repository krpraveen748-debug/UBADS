"""
Shared fixtures for backend API tests.

Every test here uses private in-memory SQLite databases, never the real
data/app.db. Two separate FastAPI dependencies are overridden:
  - `get_session` (log-collector's storage — events/behavior_features)
  - `get_db` (backend's own db/database.py Base — the new `endpoints` table)
This mirrors the same isolation pattern already used in
tests/log_collector/test_storage.py, extended to cover Phase 9's new
endpoint-identity table.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.database import Base as BackendBase
from app.db.database import get_db
from app.main import app
from app.models import dashboard_auth as dashboard_models  # noqa: F401 - registers dashboard tables
from app.models import enrollment as enrollment_models  # noqa: F401 - registers Phase 17 tables
from app.models import endpoint  # noqa: F401 - registers EndpointRecord on BackendBase.metadata
from app.repositories.pipeline_bridge import get_session, storage
from app.security import dashboard_auth

TEST_DASHBOARD_USER = "test-operator"
TEST_DASHBOARD_PASSWORD = "test-password-123456"


def _make_isolated_session(base):
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


@pytest.fixture(autouse=True)
def _never_touch_the_real_database():
    """Safety net: whatever fixtures a test uses, the app's two database
    dependencies point at throwaway in-memory databases, so a bare
    TestClient(app) can never read or write data/app.db. Fixtures such as
    `client` install their own (shared) sessions on top of this."""
    event_db = _make_isolated_session(storage.Base)
    backend_db = _make_isolated_session(BackendBase)

    def _events():
        yield event_db

    def _backend():
        yield backend_db

    app.dependency_overrides[get_session] = _events
    app.dependency_overrides[get_db] = _backend
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_session, None)
        app.dependency_overrides.pop(get_db, None)
        event_db.close()
        backend_db.close()


@pytest.fixture()
def test_session():
    session = _make_isolated_session(storage.Base)
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def endpoint_db_session():
    session = _make_isolated_session(BackendBase)
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def anon_client(test_session, endpoint_db_session):
    """Unauthenticated client (no dashboard session)."""
    def _override_events_session():
        yield test_session

    def _override_endpoint_db():
        yield endpoint_db_session

    from app.security import rate_limit

    rate_limit.reset_all()
    app.dependency_overrides[get_session] = _override_events_session
    app.dependency_overrides[get_db] = _override_endpoint_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_session, None)
        app.dependency_overrides.pop(get_db, None)


@pytest.fixture()
def client(anon_client, endpoint_db_session):
    """Client signed in through the REAL login route as a dashboard
    operator — dashboard auth is exercised, never bypassed."""
    dashboard_auth.create_user(endpoint_db_session, TEST_DASHBOARD_USER, TEST_DASHBOARD_PASSWORD)
    token = anon_client.post(
        "/api/auth/login", json={"username": TEST_DASHBOARD_USER, "password": TEST_DASHBOARD_PASSWORD}
    ).json()["access_token"]
    anon_client.headers["Authorization"] = f"Bearer {token}"
    return anon_client


def insert_fixture_event(session, event_record_id="1001", endpoint_id=None, **overrides):
    """Inserts one BACKEND-API-TEST FIXTURE event — not real collected
    data — into the isolated in-memory test database only. `endpoint_id`
    (Phase 14) attributes the fixture row the same way real ingestion
    does, for testing the Events API's per-endpoint filter."""
    base = {
        "event_id": 4624,
        "event_record_id": event_record_id,
        "event_type": "successful_logon",
        "event_category": "authentication",
        "timestamp": "2026-03-05T09:00:00.000000Z",
        "computer_name": "TEST-FIXTURE-PC",
        "username": "test.fixture.user",
        "domain": "FIXTURE-DOMAIN",
        "user_sid": "S-1-5-21-1111111111-2222222222-3333333333-1001",
        "account_type": "human_or_unknown",
        "logon_type": 2,
        "logon_type_description": "interactive",
        "raw_event_data": {},
    }
    base.update(overrides)
    return storage.insert_event(session, base, log_name="Security", endpoint_id=endpoint_id)
