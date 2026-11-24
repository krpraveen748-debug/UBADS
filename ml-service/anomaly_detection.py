"""Endpoint/user-scoped Isolation Forest training and inference."""

from __future__ import annotations

import hashlib
import io
import math
import sys
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

from feature_engineering import CATEGORIES, compute_category_availability, compute_feature_record
from model_storage import (
    ARTIFACT_PRODUCER,
    LocalModelArtifactStore,
    ModelArtifactIntegrityError,
    ModelArtifactStore,
)
from user_identity import resolve_user_id
from windowing import VALID_WINDOW_SIZES, window_bounds

MODEL_FORMAT_VERSION = 1
MODEL_VERSION_PREFIX = "isolation-forest-v1"
MINIMUM_TRAINING_WINDOWS = 20
MODEL_STALE_AFTER_DAYS = 30
EXPLANATION_METHOD = "robust_median_deviation"
ISOLATION_SCORE_WEIGHT = 0.8
PROFILE_DEVIATION_SCALE = 10.0
ANOMALY_SCORE_THRESHOLD = 0.90
SEVERITY_MEDIUM_THRESHOLD = 0.93
SEVERITY_HIGH_THRESHOLD = 0.97
BASE_FEATURES = (
    "total_activity_count",
    "number_of_categories_active",
    "distinct_active_hours",
    "off_hours_activity_count",
)
CATEGORY_FEATURES = {
    "authentication": (
        "successful_login_count",
        "failed_login_count",
        "login_failure_ratio",
        "unique_login_hours",
        "logoff_count",
    ),
    "file_activity": (
        "files_accessed",
        "files_deleted",
        "files_handle_requested",
        "unique_file_extensions",
        "unique_directories",
    ),
    "process_activity": (
        "process_count",
        "unique_process_count",
        "process_activity_frequency",
    ),
    "device_activity": ("device_event_count", "unique_devices", "new_device_count"),
    "download_related": (
        "download_related_event_count",
        "download_related_file_count",
        "download_related_activity_frequency",
    ),
}


class InsufficientTrainingData(ValueError):
    """Raised when a profile has too few observed windows for training."""


class InvalidBehaviorWindow(ValueError):
    """Raised when an input window cannot be represented safely."""


@dataclass(frozen=True)
class BehaviorWindow:
    endpoint_id: str
    profile_id: str
    user_id: str
    username: str | None
    window_start: datetime
    window_end: datetime
    window_size: str
    features: dict[str, float]
    feature_names: tuple[str, ...]


def _utc_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _profile_id(endpoint_id: str, user_id: str) -> str:
    digest = hashlib.sha256(f"{endpoint_id}\0{user_id}".encode("utf-8")).hexdigest()
    return digest[:32]


def _feature_names(category_availability: dict[str, bool]) -> tuple[str, ...]:
    names = list(BASE_FEATURES)
    for category in CATEGORIES:
        if category_availability.get(category):
            names.extend(CATEGORY_FEATURES[category])
    return tuple(names)


def _safe_feature_vector(record: dict[str, Any], names: tuple[str, ...]) -> dict[str, float]:
    result: dict[str, float] = {}
    for name in names:
        value = record.get(name)
        if value is None:
            value = 0
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise InvalidBehaviorWindow(f"Feature {name} is not numeric.")
        numeric = float(value)
        if not math.isfinite(numeric):
            raise InvalidBehaviorWindow(f"Feature {name} is not finite.")
        result[name] = numeric
    return result


def extract_behavior_windows(
    events: list[dict[str, Any]],
    *,
    window_size: str = "daily",
    now: datetime | None = None,
    include_incomplete: bool = True,
) -> list[BehaviorWindow]:
    """Aggregate normalized events using the existing feature calculations.

    Only authenticated endpoint events with a resolvable named user are
    considered. Known system/service/computer accounts are excluded.
    """
    if window_size not in VALID_WINDOW_SIZES:
        raise ValueError(f"window_size must be one of {VALID_WINDOW_SIZES}.")

    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    usernames: dict[tuple[str, str], list[str]] = defaultdict(list)
    for event in events:
        endpoint_id = event.get("endpoint_id")
        username = event.get("username")
        account_type = event.get("account_type")
        user_id = resolve_user_id(event)
        timestamp = _utc_datetime(event.get("timestamp_utc") or event.get("timestamp"))
        if (
            not isinstance(endpoint_id, str)
            or not endpoint_id.strip()
            or not isinstance(username, str)
            or not username.strip()
            or user_id == "unknown"
            or account_type not in (None, "human_or_unknown")
            or timestamp is None
            or event.get("event_category") not in CATEGORIES
        ):
            continue
        normalized = dict(event)
        normalized["timestamp_utc"] = timestamp.isoformat()
        key = (endpoint_id, user_id)
        groups[key].append(normalized)
        usernames[key].append(username.strip())

    current_time = _utc_datetime(now) if now is not None else datetime.now(timezone.utc)
    result: list[BehaviorWindow] = []
    for (endpoint_id, user_id), profile_events in groups.items():
        profile_events.sort(key=lambda event: event["timestamp_utc"])
        availability = compute_category_availability(profile_events)
        names = _feature_names(availability)
        by_window: dict[datetime, list[dict[str, Any]]] = defaultdict(list)
        for event in profile_events:
            start, end = window_bounds(datetime.fromisoformat(event["timestamp_utc"]), window_size)
            if not include_incomplete and end > current_time:
                continue
            by_window[start].append(event)

        seen_devices: set[str] = set()
        for start in sorted(by_window):
            end = window_bounds(start, window_size)[1]
            record = compute_feature_record(
                user_id,
                start,
                end,
                window_size,
                by_window[start],
                availability,
            )
            device_keys = {
                str(event.get("device_id") or event.get("device_description"))
                for event in by_window[start]
                if event.get("device_id") or event.get("device_description")
            }
            if availability.get("device_activity"):
                record["new_device_count"] = len(device_keys - seen_devices)
                seen_devices.update(device_keys)
            values = _safe_feature_vector(record, names)
            result.append(
                BehaviorWindow(
                    endpoint_id=endpoint_id,
                    profile_id=_profile_id(endpoint_id, user_id),
                    user_id=user_id,
                    username=sorted(usernames[(endpoint_id, user_id)])[0],
                    window_start=start,
                    window_end=end,
                    window_size=window_size,
                    features=values,
                    feature_names=names,
                )
            )
    return sorted(result, key=lambda row: (row.endpoint_id, row.profile_id, row.window_start))


def fit_profile_model(
    windows: list[BehaviorWindow],
    *,
    artifact_dir: Path | None = None,
    artifact_store: ModelArtifactStore | None = None,
    training_data_source: str = "real",
    minimum_windows: int = MINIMUM_TRAINING_WINDOWS,
) -> dict[str, Any]:
    if artifact_store is not None and artifact_dir is not None:
        raise ValueError("Provide either artifact_dir or artifact_store, not both.")
    if artifact_store is None:
        if artifact_dir is None:
            raise ValueError("A model artifact store or directory is required.")
        artifact_store = LocalModelArtifactStore(artifact_dir)
    if training_data_source not in {"real", "synthetic-demo"}:
        raise ValueError("training_data_source must be 'real' or 'synthetic-demo'.")
    if not windows:
        raise InsufficientTrainingData("No eligible behavioral windows were found.")
    if len(windows) < minimum_windows:
        raise InsufficientTrainingData(
            f"At least {minimum_windows} completed windows are required; found {len(windows)}."
        )
    first_window = windows[0]
    if any(
        row.endpoint_id != first_window.endpoint_id
        or row.profile_id != first_window.profile_id
        or row.window_size != first_window.window_size
        for row in windows
    ):
        raise InvalidBehaviorWindow("Training windows must belong to one endpoint/user profile.")
    names = windows[0].feature_names
    if any(row.feature_names != names for row in windows):
        raise InvalidBehaviorWindow("Feature sets differ within one behavioral profile.")

    matrix = np.asarray([[row.features[name] for name in names] for row in windows], dtype=np.float64)
    if matrix.ndim != 2 or not np.isfinite(matrix).all():
        raise InvalidBehaviorWindow("Training data contains missing or non-finite features.")
    if not np.any(np.ptp(matrix, axis=0) > 0):
        raise InsufficientTrainingData("Training windows contain no behavioral feature variation.")

    estimator = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
        n_jobs=1,
    )
    estimator.fit(matrix)
    decision_values = estimator.decision_function(matrix)
    lower, upper = np.quantile(decision_values, [0.05, 0.95]).tolist()
    if not math.isfinite(lower) or not math.isfinite(upper):
        raise InvalidBehaviorWindow("Model calibration values are not finite.")

    medians = np.median(matrix, axis=0)
    deviations = np.median(np.abs(matrix - medians), axis=0)
    trained_at = datetime.now(timezone.utc)
    metadata = {
        "format_version": MODEL_FORMAT_VERSION,
        "artifact_producer": ARTIFACT_PRODUCER,
        "model_version": f"{MODEL_VERSION_PREFIX}-{uuid.uuid4().hex[:12]}",
        "algorithm": "IsolationForest",
        "library_version": sklearn.__version__,
        "joblib_version": joblib.__version__,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "training_data_source": training_data_source,
        "training_windows": len(windows),
        "minimum_training_windows": minimum_windows,
        "feature_names": list(names),
        "endpoint_id": windows[0].endpoint_id,
        "profile_id": windows[0].profile_id,
        "username": windows[0].username,
        "window_size": windows[0].window_size,
        "first_training_window": windows[0].window_start.isoformat(),
        "latest_training_window": windows[-1].window_start.isoformat(),
        "trained_at": trained_at.isoformat(),
        "score_calibration": {"lower": float(lower), "upper": float(upper)},
        "score_method": "weighted_isolation_forest_and_robust_profile_deviation",
        "isolation_score_weight": ISOLATION_SCORE_WEIGHT,
        "profile_deviation_scale": PROFILE_DEVIATION_SCALE,
        "anomaly_score_threshold": ANOMALY_SCORE_THRESHOLD,
        "severity_thresholds": {
            "medium": SEVERITY_MEDIUM_THRESHOLD,
            "high": SEVERITY_HIGH_THRESHOLD,
        },
        "baseline_median": {name: float(value) for name, value in zip(names, medians)},
        "baseline_mad": {name: float(value) for name, value in zip(names, deviations)},
        "parameters": {
            "n_estimators": 200,
            "contamination": "auto",
            "random_state": 42,
            "max_samples": "auto",
            "max_features": 1.0,
        },
    }

    artifact_buffer = io.BytesIO()
    joblib.dump({"metadata": metadata, "estimator": estimator}, artifact_buffer, compress=3)
    artifact_store.save(
        windows[0].profile_id,
        metadata["model_version"],
        artifact_buffer.getvalue(),
        metadata,
    )
    return metadata


def load_profile_model(
    artifact_dir: Path | None,
    profile_id: str,
    *,
    artifact_store: ModelArtifactStore | None = None,
    model_version: str | None = None,
) -> dict[str, Any] | None:
    if artifact_store is not None and artifact_dir is not None:
        raise ValueError("Provide either artifact_dir or artifact_store, not both.")
    if artifact_store is None:
        if artifact_dir is None:
            raise ValueError("A model artifact store or directory is required.")
        artifact_store = LocalModelArtifactStore(artifact_dir)
    stored = artifact_store.load(profile_id, model_version)
    if stored is None:
        return None

    metadata = stored.metadata
    if (
        metadata.get("artifact_producer") != ARTIFACT_PRODUCER
        or metadata.get("format_version") != MODEL_FORMAT_VERSION
        or metadata.get("library_version") != sklearn.__version__
        or metadata.get("joblib_version") != joblib.__version__
        or metadata.get("python_version") != f"{sys.version_info.major}.{sys.version_info.minor}"
    ):
        raise ModelArtifactIntegrityError("Stored model artifact is incompatible.")
    try:
        bundle = joblib.load(io.BytesIO(stored.payload))
    except Exception:
        raise ModelArtifactIntegrityError("Stored model artifact could not be deserialized.") from None
    if (
        not isinstance(bundle, dict)
        or not isinstance(bundle.get("metadata"), dict)
        or bundle["metadata"] != metadata
        or not isinstance(bundle.get("estimator"), IsolationForest)
    ):
        raise ModelArtifactIntegrityError("Stored model artifact is invalid or incompatible.")
    return bundle


def model_is_stale(metadata: dict[str, Any], *, now: datetime | None = None) -> bool:
    trained_at = _utc_datetime(metadata.get("trained_at"))
    if trained_at is None:
        return True
    current_time = _utc_datetime(now) if now is not None else datetime.now(timezone.utc)
    return (current_time - trained_at).total_seconds() > MODEL_STALE_AFTER_DAYS * 86400


def score_behavior_window(
    window: BehaviorWindow,
    bundle: dict[str, Any],
) -> dict[str, Any]:
    metadata = bundle["metadata"]
    feature_names = tuple(metadata.get("feature_names", ()))
    if window.profile_id != metadata.get("profile_id"):
        raise InvalidBehaviorWindow("The event window does not belong to this model profile.")
    if window.feature_names != feature_names:
        raise InvalidBehaviorWindow("The event window feature set differs from the trained model.")
    vector = np.asarray([[window.features[name] for name in feature_names]], dtype=np.float64)
    if vector.shape[1] == 0 or not np.isfinite(vector).all():
        raise InvalidBehaviorWindow("The event window has missing or invalid features.")

    estimator = bundle["estimator"]
    decision_value = float(estimator.decision_function(vector)[0])
    calibration = metadata["score_calibration"]
    low = float(calibration["lower"])
    high = float(calibration["upper"])
    if high <= low:
        normalized_score = 0.0 if decision_value >= high else 1.0
    else:
        normalized_score = 1.0 - min(1.0, max(0.0, (decision_value - low) / (high - low)))
    medians = metadata["baseline_median"]
    mads = metadata["baseline_mad"]
    deviations: list[dict[str, Any]] = []
    for name in feature_names:
        observed = window.features[name]
        median = float(medians[name])
        mad = float(mads[name])
        distance = abs(observed - median)
        robust_distance = distance / (1.4826 * mad) if mad > 0 else distance
        if robust_distance > 0:
            deviations.append(
                {
                    "feature": name,
                    "observed": round(observed, 6),
                    "baseline_median": round(median, 6),
                    "direction": "above" if observed > median else "below",
                    "robust_deviation": round(robust_distance, 6),
                }
            )
    deviations.sort(key=lambda item: (-item["robust_deviation"], item["feature"]))
    max_deviation = deviations[0]["robust_deviation"] if deviations else 0.0
    profile_deviation_score = 1.0 - math.exp(-max_deviation / PROFILE_DEVIATION_SCALE)
    isolation_score_weight = float(metadata.get("isolation_score_weight", ISOLATION_SCORE_WEIGHT))
    score = round(
        isolation_score_weight * float(normalized_score)
        + (1.0 - isolation_score_weight) * profile_deviation_score,
        6,
    )
    is_anomaly = score >= float(metadata.get("anomaly_score_threshold", ANOMALY_SCORE_THRESHOLD))
    severity_thresholds = metadata.get(
        "severity_thresholds",
        {"medium": SEVERITY_MEDIUM_THRESHOLD, "high": SEVERITY_HIGH_THRESHOLD},
    )
    if score >= float(severity_thresholds["high"]):
        severity = "High"
    elif score >= float(severity_thresholds["medium"]):
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "is_anomaly": is_anomaly,
        "anomaly_score": score,
        "severity": severity if is_anomaly else "Low",
        "decision_value": decision_value,
        "isolation_forest_score": normalized_score,
        "profile_deviation_score": profile_deviation_score,
        "features": deviations[:3],
        "explanation_method": EXPLANATION_METHOD,
        "model_version": metadata["model_version"],
        "training_data_source": metadata["training_data_source"],
    }
