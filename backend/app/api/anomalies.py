"""Administrator-only anomaly detection results."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.anomaly import AnomalyDetection
from app.repositories.pipeline_bridge import get_session
from app.services.anomaly_service import serialize_anomaly

router = APIRouter(prefix="/api/anomalies", tags=["anomalies"])


@router.get("")
def list_anomalies(
    endpoint_id: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
):
    if start_time and end_time and start_time > end_time:
        raise HTTPException(status_code=422, detail="start_time must not be after end_time.")
    query = session.query(AnomalyDetection).filter(AnomalyDetection.is_anomaly.is_(True))
    if endpoint_id:
        query = query.filter(AnomalyDetection.endpoint_id == endpoint_id)
    if start_time:
        query = query.filter(AnomalyDetection.detected_at >= start_time)
    if end_time:
        query = query.filter(AnomalyDetection.detected_at <= end_time)
    total = query.count()
    severity_rows = (
        query.with_entities(AnomalyDetection.severity, func.count(AnomalyDetection.id))
        .group_by(AnomalyDetection.severity)
        .all()
    )
    records = (
        query.order_by(AnomalyDetection.detected_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "items": [serialize_anomaly(record) for record in records],
        "total": total,
        "severity_counts": {severity: count for severity, count in severity_rows},
        "limit": limit,
        "offset": offset,
    }


@router.get("/{anomaly_id}")
def get_anomaly(anomaly_id: int, session: Session = Depends(get_session)):
    record = (
        session.query(AnomalyDetection)
        .filter(
            AnomalyDetection.id == anomaly_id,
            AnomalyDetection.is_anomaly.is_(True),
        )
        .first()
    )
    if record is None:
        raise HTTPException(status_code=404, detail="Anomaly not found.")
    return serialize_anomaly(record)
