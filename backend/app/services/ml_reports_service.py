"""
Service layer for /api/ml/collection-status and /api/reports/data-quality.

Both endpoints return the exact dict already produced by ml-service's own
functions — the same ones `python feature_engineering.py --collection-
status` / `--data-quality-report` call — never a re-derived or simplified
version of that logic. The readiness/sufficiency RULES themselves live
only in ml-service/collection_status.py and ml-service/data_quality.py.
"""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.repositories.pipeline_bridge import collection_status, data_quality, storage, user_classification_diagnostics

DEFAULT_WINDOW_SIZE = "daily"


def _load_events_and_features(session: Session) -> tuple[list[dict], list[dict]]:
    try:
        events = [storage.event_record_to_dict(r) for r in storage.get_all_events(session)]
        feature_records = [
            storage.feature_record_to_dict(r) for r in storage.get_feature_records(session, limit=100000)
        ]
    except Exception as exc:  # pragma: no cover - only on genuine storage failure
        raise HTTPException(status_code=503, detail=f"Storage unavailable: {exc}") from exc
    return events, feature_records


def get_collection_status(session: Session, window_size: str = DEFAULT_WINDOW_SIZE) -> dict:
    events, feature_records = _load_events_and_features(session)
    try:
        result = collection_status.generate_collection_status(events, feature_records, window_size=window_size)
        classification = user_classification_diagnostics.generate_user_classification_report(events)
    except Exception as exc:  # pragma: no cover - only on genuine computation failure
        raise HTTPException(status_code=503, detail=f"Collection status unavailable: {exc}") from exc

    result = dict(result)
    result["human_candidate_account_count"] = classification["human_candidate_account_count"]
    return result


def get_data_quality_report(session: Session) -> dict:
    events, feature_records = _load_events_and_features(session)
    try:
        return data_quality.generate_data_quality_report(events, feature_records)
    except Exception as exc:  # pragma: no cover - only on genuine computation failure
        raise HTTPException(status_code=503, detail=f"Data quality report unavailable: {exc}") from exc
