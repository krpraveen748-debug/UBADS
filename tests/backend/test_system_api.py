"""Tests for GET /health and GET /ready using disposable database engines."""

from sqlalchemy import create_engine

from app.api import system


def test_health_still_works(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"


def test_ready_returns_200_when_database_reachable(monkeypatch):
    engine = create_engine("sqlite://")
    monkeypatch.setattr(system.storage, "engine", engine)
    try:
        response = system.readiness_check()
        assert response == {"status": "ready", "database": "ok"}
    finally:
        engine.dispose()


def test_ready_returns_503_when_database_unavailable(monkeypatch):
    class _BrokenEngine:
        def connect(self):
            raise RuntimeError("simulated database outage")

    monkeypatch.setattr(system.storage, "engine", _BrokenEngine())
    response = system.readiness_check()
    assert response.status_code == 503
    assert b"not_ready" in response.body
