"""
Tests for GET /api/users. Uses only the isolated in-memory test database
(see conftest.py) — never the real data/app.db.
"""

from tests.backend.conftest import insert_fixture_event


def test_list_users_empty_database_returns_empty_list(client):
    response = client.get("/api/users")
    assert response.status_code == 200
    assert response.json() == []


def test_list_users_includes_human_candidate(client, test_session):
    insert_fixture_event(test_session, username="alice", account_type="human_or_unknown")
    response = client.get("/api/users")
    body = response.json()
    assert len(body) == 1
    assert body[0]["username"] == "alice"
    assert body[0]["is_human_candidate"] is True
    # Privacy: raw SID never returned, only a presence flag.
    assert "user_sid" not in body[0]
    assert body[0]["sid_present"] is True


def test_list_users_excludes_service_accounts(client, test_session):
    insert_fixture_event(
        test_session,
        username="SYSTEM",
        domain="NT AUTHORITY",
        user_sid="S-1-5-18",
        account_type="system",
    )
    response = client.get("/api/users")
    assert response.json() == []
