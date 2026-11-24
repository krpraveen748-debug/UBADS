"""User-facing endpoint request routes (Phase 17). Any signed-in account may
create and read ITS OWN requests; nothing here can see anyone else's."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from starlette.background import BackgroundTask
from starlette.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.dashboard_auth import DashboardUser
from app.schemas.endpoint_requests import EndpointRequestCreate, EndpointRequestOut
from app.security.dashboard_auth import get_current_user
from app.services import endpoint_request_service, enrollment_service, installer_download_service

router = APIRouter(prefix="/api/endpoint-requests", tags=["endpoint-requests"])


@router.post("", response_model=EndpointRequestOut, status_code=201)
def create_request(
    body: EndpointRequestCreate, user: DashboardUser = Depends(get_current_user), session: Session = Depends(get_db)
):
    return endpoint_request_service.create_request(session, user, body)


@router.get("/my", response_model=list[EndpointRequestOut])
def my_requests(user: DashboardUser = Depends(get_current_user), session: Session = Depends(get_db)):
    return endpoint_request_service.list_my_requests(session, user)


@router.get("/{request_id}", response_model=EndpointRequestOut)
def my_request(request_id: str, user: DashboardUser = Depends(get_current_user), session: Session = Depends(get_db)):
    return endpoint_request_service.get_my_request(session, user, request_id)


@router.get("/{request_id}/download-info")
def download_info(request_id: str, user: DashboardUser = Depends(get_current_user), session: Session = Depends(get_db)):
    """Installer metadata for an APPROVED request owned by the caller (403 otherwise)."""
    return installer_download_service.download_info(session, user, request_id)


@router.post("/{request_id}/enrollment-package")
def enrollment_package(request_id: str, user: DashboardUser = Depends(get_current_user), session: Session = Depends(get_db)):
    """Mints a fresh single-use enrollment code for the OWNER of an approved request
    and returns the generic installer under a file name that carries it
    (UBADS-Agent-Setup--<code>.exe) so the installer can enroll without typing.
    POST, never GET: a link, prefetch or page refresh cannot trigger it, and a repeat
    call only supersedes the previous unredeemed code - it never consumes one."""
    installer_download_service.authorize(session, user, request_id)
    enrollment_service.check_mint_rate_limit(user)
    artifact, size = installer_download_service.prepare_installer_download()
    try:
        minted = enrollment_service.mint_package(session, user, request_id)
    except Exception:
        artifact.close()
        raise

    def stream():
        try:
            while chunk := artifact.read(1 << 20):
                yield chunk
        finally:
            artifact.close()

    filename = f"UBADS-Agent-Setup--{minted.code}.exe"
    return StreamingResponse(
        stream(),
        media_type="application/octet-stream",
        headers={
            "Cache-Control": "no-store",
            "Content-Length": str(size),
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Enrollment-Expires-At": minted.expires_at.isoformat(),
        },
        background=BackgroundTask(artifact.close),
    )
