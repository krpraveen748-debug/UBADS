"""Phase 17 stage 3A/3D: notifications API and approved-download authorization.
Isolated in-memory database; the installer is a tiny stub file except where a
test deliberately checks the real build output location."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import settings
from app.models.enrollment import EndpointRequest, Notification
from tests.backend.test_endpoint_requests import _login_client, _register, _request_body

STUB = b"MZ-stub-installer-bytes"


@pytest.fixture()
def installer(tmp_path, monkeypatch):
    path = tmp_path / "UBADS-Agent-Setup.exe"
    path.write_bytes(STUB)
    monkeypatch.setattr(settings, "installer_path", str(path))
    return path


@pytest.fixture()
def users(anon_client):
    _register(anon_client, "alice")
    _register(anon_client, "bob")
    return _login_client("alice"), _login_client("bob")


def _new_request(user, **over):
    r = user.post("/api/endpoint-requests", json=_request_body(**over))
    assert r.status_code == 201
    return r.json()["id"]


def _admin(client, rid, action, **body):
    r = client.post(f"/api/admin/endpoint-requests/{rid}/{action}", json=body)
    assert r.status_code == 200, r.text
    return r.json()


# --- notifications ------------------------------------------------------------


def test_notifications_created_for_submission_approval_rejection_revocation(client, users):
    alice, _ = users
    a, b, c = _new_request(alice), _new_request(alice), _new_request(alice)
    _admin(client, a, "approve")
    _admin(client, a, "revoke", reason="no longer needed")
    _admin(client, b, "reject", reason="not authorized")
    _admin(client, c, "approve")
    kinds = [n["kind"] for n in alice.get("/api/notifications").json()]
    assert kinds.count("request.submitted") == 3
    assert kinds.count("request.approved") == 2 and kinds.count("request.rejected") == 1 and kinds.count("request.revoked") == 1
    notes = {n["kind"]: n for n in alice.get("/api/notifications").json()}
    assert notes["request.rejected"]["request_id"] == b and "not authorized" in notes["request.rejected"]["message"]


def test_list_unread_count_mark_read_and_read_all(users):
    alice, _ = users
    for _ in range(3):
        _new_request(alice)
    assert alice.get("/api/notifications/unread-count").json() == {"unread": 3}
    items = alice.get("/api/notifications").json()
    assert len(items) == 3 and all(not n["read"] and n["read_at"] is None for n in items)
    assert [n["id"] for n in items] == sorted((n["id"] for n in items), reverse=True)  # newest first

    one = alice.post(f"/api/notifications/{items[0]['id']}/read").json()
    assert one["read"] is True and one["read_at"]
    again = alice.post(f"/api/notifications/{items[0]['id']}/read").json()  # idempotent
    assert again["read_at"] == one["read_at"]
    assert alice.get("/api/notifications/unread-count").json() == {"unread": 2}
    assert len(alice.get("/api/notifications", params={"unread_only": True}).json()) == 2

    assert alice.post("/api/notifications/read-all").json() == {"marked": 2}
    assert alice.get("/api/notifications/unread-count").json() == {"unread": 0}
    assert alice.post("/api/notifications/read-all").json() == {"marked": 0}
    assert alice.get("/api/notifications", params={"limit": 1}).json().__len__() == 1


def test_users_cannot_read_or_mark_each_others_notifications(users, endpoint_db_session):
    alice, bob = users
    _new_request(alice)
    alice_note = alice.get("/api/notifications").json()[0]["id"]
    assert bob.get("/api/notifications").json() == []
    assert bob.get("/api/notifications/unread-count").json() == {"unread": 0}
    assert bob.post(f"/api/notifications/{alice_note}/read").status_code == 404
    assert bob.post("/api/notifications/read-all").json() == {"marked": 0}
    assert alice.get("/api/notifications/unread-count").json() == {"unread": 1}  # untouched by bob
    assert endpoint_db_session.get(Notification, alice_note).read_at is None


def test_admin_notifications_are_the_admins_own_and_never_the_users(client, users):
    alice, _ = users
    _new_request(alice)
    admin_kinds = [n["kind"] for n in client.get("/api/notifications").json()]
    assert admin_kinds == ["request.pending"]  # the admin is alerted to review...
    assert "request.submitted" not in admin_kinds  # ...but cannot see the user's own copy
    assert [n["kind"] for n in alice.get("/api/notifications").json()] == ["request.submitted"]  # and users never see admin alerts


def test_notifications_require_login(anon_client):
    assert anon_client.get("/api/notifications").status_code == 401
    assert anon_client.get("/api/notifications/unread-count").status_code == 401
    assert anon_client.post("/api/notifications/1/read").status_code == 401
    assert anon_client.post("/api/notifications/read-all").status_code == 401


# --- approved download --------------------------------------------------------


def test_approved_owner_can_download_an_enrollment_package(client, users, installer, endpoint_db_session):
    alice, _ = users
    rid = _new_request(alice, requested_scope=["authentication", "process_activity"])
    _admin(client, rid, "approve", approved_scope=["authentication"])

    info = alice.get(f"/api/endpoint-requests/{rid}/download-info").json()
    assert info["approved_scope"] == ["authentication"]  # the narrowed scope the admin granted
    assert info["installer"]["available"] and info["installer"]["size_bytes"] == len(STUB) and len(info["installer"]["sha256"]) == 64
    assert info["automatic_enrollment"] is True and info["approval_expires_at"]
    assert not any(k in str(info).lower() for k in ("token", "credential", "secret", "password"))

    r = alice.post(f"/api/endpoint-requests/{rid}/enrollment-package")
    assert r.status_code == 200 and r.content == STUB
    assert "UBADS-Agent-Setup--ubads1." in r.headers["content-disposition"]
    assert r.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("setup", ["pending", "rejected", "revoked"])
def test_download_denied_unless_approved(client, users, installer, setup):
    alice, _ = users
    rid = _new_request(alice)
    if setup == "rejected":
        _admin(client, rid, "reject", reason="not today")
    if setup == "revoked":
        _admin(client, rid, "approve")
        _admin(client, rid, "revoke", reason="policy change")
    for method, path in (("post", "enrollment-package"), ("get", "download-info")):
        r = getattr(alice, method)(f"/api/endpoint-requests/{rid}/{path}")
        assert r.status_code == 403, (setup, path)
        assert STUB.decode() not in r.text


def test_download_denied_after_approval_expires(client, users, installer, endpoint_db_session):
    alice, _ = users
    rid = _new_request(alice)
    _admin(client, rid, "approve")
    endpoint_db_session.get(EndpointRequest, rid).approval_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    endpoint_db_session.commit()
    r = alice.post(f"/api/endpoint-requests/{rid}/enrollment-package")
    assert r.status_code == 403 and "expired" in r.json()["detail"].lower()
    assert alice.get(f"/api/endpoint-requests/{rid}").json()["status"] == "EXPIRED"


def test_download_is_owner_only_and_requires_login(client, users, installer):
    from fastapi.testclient import TestClient

    from app.main import app

    anonymous = TestClient(app)  # `client` and `anon_client` are one object once signed in
    alice, bob = users
    rid = _new_request(alice)
    _admin(client, rid, "approve")
    for method, path in (("post", "enrollment-package"), ("get", "download-info")):
        assert getattr(bob, method)(f"/api/endpoint-requests/{rid}/{path}").status_code == 404
        assert getattr(anonymous, method)(f"/api/endpoint-requests/{rid}/{path}").status_code == 401
        assert getattr(alice, method)(f"/api/endpoint-requests/missing/{path}").status_code == 404
    # an approved request does not unlock downloads for the admin account either unless it is the admin's own
    assert client.post(f"/api/endpoint-requests/{rid}/enrollment-package").status_code == 404


def test_missing_installer_file_is_a_clear_503_and_not_a_leak(client, users, tmp_path, monkeypatch):
    alice, _ = users
    monkeypatch.setattr(settings, "installer_path", str(tmp_path / "nope.exe"))
    rid = _new_request(alice)
    _admin(client, rid, "approve")
    assert alice.post(f"/api/endpoint-requests/{rid}/enrollment-package").status_code == 503
    assert alice.get(f"/api/endpoint-requests/{rid}/download-info").json()["installer"]["available"] is False


def test_default_installer_location_is_the_real_build_output():
    """Verifies the location the backend links to by default exists."""
    path = settings.resolved_installer_path
    assert path.parts[-3:] == ("agent", "dist", "UBADS-Agent-Setup.exe")
    assert path.is_file() and path.stat().st_size > 1_000_000


# --- users cannot change status or scope ---------------------------------------


def test_user_cannot_set_status_or_alter_the_approved_scope(client, users):
    alice, bob = users
    r = alice.post(
        "/api/endpoint-requests",
        json=_request_body(status="APPROVED", approved_scope=["authentication", "file_activity"], decided_by="alice"),
    ).json()
    assert r["status"] == "PENDING" and r["approved_scope"] is None and r["decided_by"] is None
    rid = r["id"]
    _admin(client, rid, "approve", approved_scope=["authentication"])
    base = f"/api/endpoint-requests/{rid}"
    for method in ("put", "patch", "delete"):
        assert alice.request(method.upper(), base, json={"approved_scope": ["file_activity"], "status": "APPROVED"}).status_code == 405
    # nor can they approve themselves, or grow the scope through the admin routes
    assert alice.post(f"/api/admin/endpoint-requests/{rid}/approve", json={"approved_scope": ["file_activity"]}).status_code == 403
    assert alice.get(base).json()["approved_scope"] == ["authentication"]
