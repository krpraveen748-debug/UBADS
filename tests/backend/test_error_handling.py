"""
Tests for app/core/errors.py — unhandled exceptions must never leak
internal detail to the client, only a generic 500.
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.errors import register_error_handlers


def test_unhandled_exception_returns_generic_500_without_leaking_detail():
    app = FastAPI()
    register_error_handlers(app)

    @app.get("/boom")
    def boom():
        raise ValueError("sensitive internal detail that must never reach the client")

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/boom")

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error."}
    assert "sensitive internal detail" not in response.text
