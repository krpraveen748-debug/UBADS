"""Authorization and private storage access for Windows agent installers."""

from __future__ import annotations

import hashlib
import logging
import tempfile
from functools import lru_cache
from pathlib import Path
from tempfile import SpooledTemporaryFile
from typing import BinaryIO

from azure.core import MatchConditions
from azure.core.exceptions import AzureError, ResourceNotFoundError
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.dashboard_auth import DashboardUser
from app.models.enrollment import STATUS_APPROVED, STATUS_ENROLLMENT_PENDING, EndpointRequest
from app.services.admin_request_service import expire_stale

INSTALLER_FILENAME = "UBADS-Agent-Setup.exe"
_DOWNLOAD_BUFFER_BYTES = 1 << 20
_SPOOL_MEMORY_BYTES = 8 << 20
_hash_cache: dict[tuple[str, int, str], str] = {}
logger = logging.getLogger(__name__)

_DENIAL = {
    "PENDING": "This request is still waiting for administrator approval.",
    "REJECTED": "This request was rejected, so the installer is not available for it.",
    "REVOKED": "This authorization was revoked, so the installer is no longer available for it.",
    "EXPIRED": "This approval expired. Please submit a new request.",
    "ENROLLED": "An agent is already enrolled for this request.",
}


@lru_cache(maxsize=8)
def _azure_blob_client(account_url: str, container: str, blob_name: str):
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import BlobServiceClient

    return BlobServiceClient(account_url=account_url, credential=DefaultAzureCredential()).get_blob_client(
        container=container,
        blob=blob_name,
    )


def installer_path() -> Path:
    return settings.resolved_installer_path


def _blob_client():
    if not settings.azure_storage_account_url:
        raise HTTPException(status_code=503, detail="The installer is not available on this server.")
    return _azure_blob_client(
        settings.azure_storage_account_url,
        settings.azure_installer_container,
        settings.azure_installer_blob_name,
    )


def _storage_unavailable() -> HTTPException:
    logger.warning("Installer storage is unavailable.")
    return HTTPException(status_code=503, detail="The installer is temporarily unavailable. Contact an administrator.")


def _blob_digest(blob, properties) -> str:
    key = (
        f"azure:{settings.azure_installer_container}/{settings.azure_installer_blob_name}",
        int(properties.size),
        str(properties.etag or ""),
    )
    if key not in _hash_cache:
        digest = hashlib.sha256()
        downloader = blob.download_blob(etag=properties.etag, match_condition=MatchConditions.IfNotModified)
        for chunk in downloader.chunks():
            digest.update(chunk)
        _hash_cache.clear()
        _hash_cache[key] = digest.hexdigest()
    return _hash_cache[key]


def installer_info() -> dict:
    if settings.installer_storage_provider == "azure_blob":
        try:
            blob = _blob_client()
            properties = blob.get_blob_properties()
            return {
                "available": True,
                "filename": INSTALLER_FILENAME,
                "size_bytes": int(properties.size),
                "sha256": _blob_digest(blob, properties),
            }
        except ResourceNotFoundError:
            return {"available": False, "filename": INSTALLER_FILENAME, "size_bytes": None, "sha256": None}
        except AzureError:
            raise _storage_unavailable() from None

    path = installer_path()
    if not path.is_file():
        return {"available": False, "filename": INSTALLER_FILENAME, "size_bytes": None, "sha256": None}
    try:
        stat = path.stat()
        key = (str(path), stat.st_size, str(stat.st_mtime_ns))
        if key not in _hash_cache:
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(_DOWNLOAD_BUFFER_BYTES), b""):
                    digest.update(chunk)
            _hash_cache.clear()
            _hash_cache[key] = digest.hexdigest()
    except OSError:
        raise _storage_unavailable() from None
    return {
        "available": True,
        "filename": INSTALLER_FILENAME,
        "size_bytes": stat.st_size,
        "sha256": _hash_cache[key],
    }


def prepare_installer_download() -> tuple[BinaryIO, int]:
    """Fetch and spool the complete artifact before issuing an enrollment code."""
    spool = tempfile.SpooledTemporaryFile(max_size=_SPOOL_MEMORY_BYTES, mode="w+b")
    digest = hashlib.sha256()
    try:
        if settings.installer_storage_provider == "azure_blob":
            blob = _blob_client()
            properties = blob.get_blob_properties()
            cache_key = (
                f"azure:{settings.azure_installer_container}/{settings.azure_installer_blob_name}",
                int(properties.size),
                str(properties.etag or ""),
            )
            downloader = blob.download_blob(
                etag=properties.etag,
                match_condition=MatchConditions.IfNotModified,
            )
            for chunk in downloader.chunks():
                spool.write(chunk)
                digest.update(chunk)
        else:
            path = installer_path()
            if not path.is_file():
                raise ResourceNotFoundError(message="Installer missing")
            stat = path.stat()
            cache_key = (str(path), stat.st_size, str(stat.st_mtime_ns))
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(_DOWNLOAD_BUFFER_BYTES), b""):
                    spool.write(chunk)
                    digest.update(chunk)
        size = spool.tell()
        if size == 0:
            raise ResourceNotFoundError(message="Installer is empty")
        _hash_cache.clear()
        _hash_cache[cache_key] = digest.hexdigest()
        spool.seek(0)
        return spool, size
    except ResourceNotFoundError:
        spool.close()
        raise HTTPException(status_code=503, detail="The installer is not available on this server.") from None
    except (AzureError, OSError):
        spool.close()
        raise _storage_unavailable() from None


def authorize(session: Session, user: DashboardUser, request_id: str) -> EndpointRequest:
    """Returns the request iff `user` owns it and it is currently approved."""
    expire_stale(session)
    req = session.get(EndpointRequest, request_id)
    if req is None or req.username != user.username:
        raise HTTPException(status_code=404, detail="Request not found.")
    session.refresh(req)
    if req.status not in (STATUS_APPROVED, STATUS_ENROLLMENT_PENDING):
        raise HTTPException(
            status_code=403,
            detail=_DENIAL.get(req.status, "The installer is not available for this request."),
        )
    return req


def download_info(session: Session, user: DashboardUser, request_id: str) -> dict:
    req = authorize(session, user, request_id)
    return {
        "request_id": req.id,
        "status": req.status,
        "approved_scope": [s for s in (req.approved_scope or "").split(",") if s],
        "approval_expires_at": req.approval_expires_at.isoformat() if req.approval_expires_at else None,
        "installer": installer_info(),
        "automatic_enrollment": True,
    }
