from __future__ import annotations

import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.anomaly import AnomalyDetection
from app.repositories.pipeline_bridge import storage
from anomaly_detection import (
    MINIMUM_TRAINING_WINDOWS,
    InsufficientTrainingData,
    extract_behavior_windows,
    fit_profile_model,
    load_profile_model,
    model_is_stale,
    score_behavior_window,
)
from model_storage import ModelStorageError, configured_model_artifact_store

logger = logging.getLogger(__name__)


def _read_events(session: Session, endpoint_id: str | None = None) -> list[dict[str, Any]]:
    records = storage.get_all_events(session, endpoint_id=endpoint_id)
    return [storage.event_record_to_dict(record) for record in records]


def _group_windows(events: list[dict[str, Any]], *, include_incomplete: bool = False):
    windows = extract_behavior_windows(events, include_incomplete=include_incomplete)
    grouped = defaultdict(list)
    for window in windows:
        grouped[window.profile_id].append(window)
    return grouped


def _model_artifact_store():
    return configured_model_artifact_store(
        settings.model_storage_provider,
        str(settings.anomaly_model_dir),
        settings.azure_storage_account_url,
        settings.azure_storage_container,
    )


def train_models(session: Session) -> dict[str, Any]:
    windows_by_profile = _group_windows(_read_events(session))
    artifact_store = _model_artifact_store()
    trained: list[dict[str, Any]] = []
    insufficient: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []

    for profile_windows in windows_by_profile.values():
        profile = profile_windows[0]
        profile_summary = {
            "endpoint_id": profile.endpoint_id,
            "profile_id": profile.profile_id,
            "username": profile.username,
            "completed_windows": len(profile_windows),
        }
        try:
            metadata = fit_profile_model(profile_windows, artifact_store=artifact_store)
            trained.append(
                {
                    **profile_summary,
                    "model_version": metadata["model_version"],
                    "training_data_source": metadata["training_data_source"],
                    "trained_at": metadata["trained_at"],
                }
            )
        except InsufficientTrainingData as exc:
            insufficient.append({**profile_summary, "reason": str(exc)})
        except (ModelStorageError, OSError, ValueError) as exc:
            logger.exception("Anomaly model training failed.")
            failed.append({**profile_summary, "reason": str(exc)})

    return {
        "algorithm": "IsolationForest",
        "minimum_training_windows": MINIMUM_TRAINING_WINDOWS,
        "trained_profiles": trained,
        "insufficient_profiles": insufficient,
        "failed_profiles": failed,
        "training_data_source": "real",
    }


def get_model_status(session: Session) -> dict[str, Any]:
    windows_by_profile = _group_windows(_read_events(session))
    artifact_store = _model_artifact_store()
    profiles: list[dict[str, Any]] = []
    for profile_windows in windows_by_profile.values():
        first = profile_windows[0]
        status: dict[str, Any] = {
            "endpoint_id": first.endpoint_id,
            "profile_id": first.profile_id,
            "username": first.username,
            "completed_windows": len(profile_windows),
            "required_windows": MINIMUM_TRAINING_WINDOWS,
            "status": "insufficient-data",
            "model_version": None,
            "training_data_source": None,
            "trained_at": None,
        }
        try:
            bundle = load_profile_model(None, first.profile_id, artifact_store=artifact_store)
        except Exception:
            logger.exception("Could not load a model artifact.")
            status["status"] = "invalid-model"
            profiles.append(status)
            continue
        if bundle:
            metadata = bundle["metadata"]
            if tuple(metadata.get("feature_names", ())) != first.feature_names:
                status["status"] = "needs-retraining"
                profiles.append(status)
                continue
            status.update(
                {
                    "status": "stale" if model_is_stale(metadata) else "ready",
                    "model_version": metadata["model_version"],
                    "training_data_source": metadata["training_data_source"],
                    "trained_at": metadata["trained_at"],
                    "training_windows": metadata["training_windows"],
                }
            )
        profiles.append(status)
    return {
        "algorithm": "IsolationForest",
        "minimum_training_windows": MINIMUM_TRAINING_WINDOWS,
        "profiles": profiles,
        "trained_profiles": sum(profile["status"] in {"ready", "stale"} for profile in profiles),
        "insufficient_profiles": sum(profile["status"] == "insufficient-data" for profile in profiles),
    }


def score_endpoint_events(session: Session, endpoint_id: str) -> dict[str, int]:
    events = _read_events(session, endpoint_id=endpoint_id)
    latest_by_profile = {}
    for window in extract_behavior_windows(events, include_incomplete=True):
        previous = latest_by_profile.get(window.profile_id)
        if previous is None or window.window_start > previous.window_start:
            latest_by_profile[window.profile_id] = window

    detections = 0
    skipped = 0
    artifact_store = _model_artifact_store()
    for profile_id, window in latest_by_profile.items():
        try:
            bundle = load_profile_model(None, profile_id, artifact_store=artifact_store)
            if bundle is None or model_is_stale(bundle["metadata"]):
                skipped += 1
                continue
            result = score_behavior_window(window, bundle)
        except Exception:
            logger.exception("Anomaly inference failed.")
            skipped += 1
            continue

        if not result["is_anomaly"]:
            continue
        existing = (
            session.query(AnomalyDetection)
            .filter(
                AnomalyDetection.profile_id == profile_id,
                AnomalyDetection.window_start == window.window_start,
                AnomalyDetection.window_size == window.window_size,
                AnomalyDetection.model_version == result["model_version"],
            )
            .first()
        )
        if existing:
            continue
        session.add(
            AnomalyDetection(
                endpoint_id=endpoint_id,
                profile_id=profile_id,
                username=window.username,
                window_start=window.window_start,
                window_end=window.window_end,
                window_size=window.window_size,
                anomaly_score=result["anomaly_score"],
                severity=result["severity"],
                explanation_json=json.dumps(
                    {
                        "features": result["features"],
                        "method": result["explanation_method"],
                        "interpretation": (
                            "Heuristic deviations from the training profile; "
                            "not causal feature importance or proof of an incident."
                        ),
                    },
                    separators=(",", ":"),
                ),
                explanation_method=result["explanation_method"],
                model_version=result["model_version"],
                training_data_source=result["training_data_source"],
                detected_at=datetime.now(timezone.utc),
                is_anomaly=True,
            )
        )
        detections += 1

    if detections:
        session.commit()
    return {"detections_recorded": detections, "profiles_skipped": skipped}


def serialize_anomaly(record: AnomalyDetection) -> dict[str, Any]:
    return {
        "id": record.id,
        "endpoint_id": record.endpoint_id,
        "profile_id": record.profile_id,
        "username": record.username,
        "window_start": record.window_start.isoformat(),
        "window_end": record.window_end.isoformat(),
        "window_size": record.window_size,
        "anomaly_score": record.anomaly_score,
        "severity": record.severity,
        "explanation": json.loads(record.explanation_json),
        "model_version": record.model_version,
        "training_data_source": record.training_data_source,
        "detected_at": record.detected_at.isoformat(),
        "is_anomaly": record.is_anomaly,
    }
