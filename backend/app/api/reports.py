"""GET /api/reports/data-quality — see backend/app/services/ml_reports_service.py."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.repositories.pipeline_bridge import get_session
from app.services import ml_reports_service

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/data-quality")
def data_quality_report(session: Session = Depends(get_session)):
    return ml_reports_service.get_data_quality_report(session)
