"""GET /api/ml/collection-status — see backend/app/services/ml_reports_service.py."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.repositories.pipeline_bridge import get_session
from app.services import anomaly_service, ml_reports_service, synthetic_experiment_service

router = APIRouter(prefix="/api/ml", tags=["ml"])


@router.get("/collection-status")
def collection_status(
    window_size: str = Query("daily", pattern="^(hourly|daily)$"),
    session: Session = Depends(get_session),
):
    return ml_reports_service.get_collection_status(session, window_size=window_size)


@router.get("/anomaly-status")
def anomaly_status(session: Session = Depends(get_session)):
    return anomaly_service.get_model_status(session)


@router.post("/train-anomaly-models")
def train_anomaly_models(session: Session = Depends(get_session)):
    return anomaly_service.train_models(session)


@router.get("/synthetic-experiment")
def synthetic_experiment_summary():
    try:
        return synthetic_experiment_service.get_summary()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/synthetic-experiment/samples")
def synthetic_experiment_samples(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    try:
        return synthetic_experiment_service.get_samples(limit=limit, offset=offset)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
