import logging

from sqlalchemy import create_engine, inspect
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from app.main import app
from app.api import system

client = TestClient(app)


def test_health_check(caplog):
    caplog.set_level(logging.INFO, logger="app.main")
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    response = client.get("/health?token=never-log-this")
    assert response.status_code == 200
    app_logs = (record.getMessage() for record in caplog.records if record.name == "app.main")
    assert all("never-log-this" not in message for message in app_logs)


class _Connection:
    def __init__(self, fail=False):
        self.fail = fail

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def execute(self, _statement):
        if self.fail:
            raise RuntimeError("database unavailable")


class _Engine:
    def __init__(self, fail=False):
        self.fail = fail
        self.connected = False

    def connect(self):
        self.connected = True
        return _Connection(self.fail)


def test_ready_checks_identity_and_event_databases(monkeypatch):
    identity_engine = _Engine()
    event_engine = _Engine()
    monkeypatch.setattr(system, "identity_engine", identity_engine)
    monkeypatch.setattr(system.storage, "engine", event_engine)

    response = client.get("/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "database": "ok"}
    assert identity_engine.connected
    assert event_engine.connected


def test_app_startup_health_and_readiness_use_empty_isolated_databases(monkeypatch):
    identity_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    event_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    monkeypatch.setattr(system, "identity_engine", identity_engine)
    monkeypatch.setattr(system.storage, "engine", event_engine)

    with TestClient(app) as isolated_client:
        assert isolated_client.get("/health").status_code == 200
        assert isolated_client.get("/ready").status_code == 200

    assert inspect(identity_engine).get_table_names() == []
    assert inspect(event_engine).get_table_names() == []
    identity_engine.dispose()
    event_engine.dispose()


def test_ready_returns_unavailable_when_a_database_fails(monkeypatch):
    identity_engine = _Engine(fail=True)
    event_engine = _Engine()
    monkeypatch.setattr(system, "identity_engine", identity_engine)
    monkeypatch.setattr(system.storage, "engine", event_engine)

    response = client.get("/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "not_ready", "database": "unavailable"}
    assert identity_engine.connected
    assert not event_engine.connected
