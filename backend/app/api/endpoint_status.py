"""GET /api/endpoints/status — see backend/app/services/endpoint_status_service.py."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.repositories.pipeline_bridge import get_session
from app.schemas.endpoint_status import EndpointStatus
from app.services import endpoint_status_service

router = APIRouter(prefix="/api/endpoints", tags=["endpoints"])


@router.get("/status", response_model=EndpointStatus)
def endpoint_status(session: Session = Depends(get_session)):
    return endpoint_status_service.get_endpoint_status(session)
