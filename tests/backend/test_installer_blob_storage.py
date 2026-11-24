"""Private Azure Blob installer delivery through the approved user portal."""

from hashlib import sha256
from types import SimpleNamespace

import pytest
from azure.core import MatchConditions
from azure.core.exceptions import ResourceNotFoundError

from app.core.config import settings
from app.models.enrollment import EnrollmentAuthorization, EndpointRequest
from app.services import installer_download_service
from tests.backend.test_endpoint_requests import _login_client, _register, _request_body

STUB = b"MZ-verified-private-installer"


class _FakeDownloader:
    def chunks(self):
        yield STUB[:7]
        yield STUB[7:]


class _FakeBlob:
    def get_blob_properties(self):
        return SimpleNamespace(size=len(STUB), etag='"ubads-installer-v1"')

    def download_blob(self, *, etag, match_condition):
        assert etag == '"ubads-installer-v1"'
        assert match_condition == MatchConditions.IfNotModified
        return _FakeDownloader()


@pytest.fixture()
def azure_installer(monkeypatch):
    monkeypatch.setattr(settings, "installer_storage_provider", "azure_blob")
    monkeypatch.setattr(settings, "azure_storage_account_url", "https://storage.example.invalid")
    monkeypatch.setattr(settings, "azure_installer_container", "ubads-installers")
    monkeypatch.setattr(settings, "azure_installer_blob_name", "releases/UBADS-Agent-Setup.exe")
    installer_download_service._hash_cache.clear()
    blob = _FakeBlob()

    monkeypatch.setattr(installer_download_service, "_blob_client", lambda: blob)
    return blob


@pytest.fixture()
def alice(anon_client):
    _register(anon_client, "alice")
    return _login_client("alice")


def _approved_request(admin, owner):
    response = owner.post(
        "/api/endpoint-requests",
        json=_request_body(requested_scope=["authentication", "process_activity"]),
    )
    assert response.status_code == 201
    request_id = response.json()["id"]
    approved = admin.post(
        f"/api/admin/endpoint-requests/{request_id}/approve",
        json={"approved_scope": ["authentication"]},
    )
    assert approved.status_code == 200
    return request_id


def test_approved_owner_receives_the_private_blob_as_an_endpoint_package(
    client, alice, azure_installer
):
    request_id = _approved_request(client, alice)

    info = alice.get(f"/api/endpoint-requests/{request_id}/download-info")
    assert info.status_code == 200
    assert info.json()["installer"] == {
        "available": True,
        "filename": "UBADS-Agent-Setup.exe",
        "size_bytes": len(STUB),
        "sha256": sha256(STUB).hexdigest(),
    }
    assert info.json()["automatic_enrollment"] is True

    response = alice.post(f"/api/endpoint-requests/{request_id}/enrollment-package")
    assert response.status_code == 200
    assert response.content == STUB
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-length"] == str(len(STUB))
    assert "UBADS-Agent-Setup--ubads1." in response.headers["content-disposition"]
    assert "ubads1." not in str(response.request.url)
    assert response.headers.get("location") is None


def test_missing_private_blob_does_not_issue_or_consume_an_enrollment_code(
    client, alice, monkeypatch, endpoint_db_session
):
    monkeypatch.setattr(settings, "installer_storage_provider", "azure_blob")
    monkeypatch.setattr(settings, "azure_storage_account_url", "https://storage.example.invalid")
    monkeypatch.setattr(settings, "azure_installer_container", "ubads-installers")
    monkeypatch.setattr(settings, "azure_installer_blob_name", "releases/UBADS-Agent-Setup.exe")

    class MissingBlob:
        def get_blob_properties(self):
            raise ResourceNotFoundError(message="Not found")

    monkeypatch.setattr(installer_download_service, "_blob_client", MissingBlob)
    request_id = _approved_request(client, alice)

    response = alice.post(f"/api/endpoint-requests/{request_id}/enrollment-package")
    assert response.status_code == 503
    assert endpoint_db_session.query(EnrollmentAuthorization).count() == 0
    assert endpoint_db_session.get(EndpointRequest, request_id).status == "APPROVED"


def test_generic_get_download_is_not_a_package_issuance_route(client, alice, azure_installer):
    request_id = _approved_request(client, alice)
    response = alice.get(f"/api/endpoint-requests/{request_id}/download")
    assert response.status_code == 404
