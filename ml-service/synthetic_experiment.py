"""Read-only real-data baseline and isolated synthetic ML experiments.

This module deliberately keeps synthetic experiments outside the production
training path. Real events are joined from the exported source IDs, while
feature extraction, user resolution, model fitting, and scoring are delegated
to the existing UBADS ML implementation.
"""

from __future__ import annotations

import csv
import json
import math
import random
import sqlite3
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import median, pstdev
from typing import Any, Iterable

from anomaly_detection import (
    MINIMUM_TRAINING_WINDOWS,
    BehaviorWindow,
    InsufficientTrainingData,
    extract_behavior_windows,
    fit_profile_model,
    load_profile_model,
    score_behavior_window,
)

REAL_PROVENANCE = "real-source"
SYNTHETIC_NORMAL_PROVENANCE = "synthetic_normal"
SYNTHETIC_ABNORMAL_PROVENANCE = "synthetic_abnormal"
SYNTHETIC_MODEL_VERSION_PREFIX = "synthetic-experiment/"
RISK_SCORE_METHOD_VERSION = "behavior-risk-v1"
MIN_REFERENCE_OBSERVATIONS = 2
REQUIRED_CSV_COLUMNS = (
    "source_event_id",
    "event_uid",
    "event_id",
    "timestamp_utc",
    "endpoint_id",
    "derived_user_id",
    "username_masked",
    "computer_name_masked",
    "log_name",
    "event_category",
    "event_type",
    "account_type",
    "logon_type",
    "logon_type_description",
    "process_name_masked",
    "parent_process_name_masked",
    "process_id",
    "parent_process_id",
    "file_extension",
    "file_action",
    "device_class",
    "device_action",
    "feature_version",
    "data_source",
    "provenance_status",
)


@dataclass(frozen=True)
class SyntheticGenerationConfig:
    seed: int = 42
    normal_samples: int = 40
    abnormal_samples: int = 20
    noise_fraction: float = 0.10
    abnormal_multiplier: float = 3.0
    min_reference_observations: int = MIN_REFERENCE_OBSERVATIONS

    def __post_init__(self) -> None:
        if self.normal_samples < MINIMUM_TRAINING_WINDOWS:
            raise ValueError(
                f"normal_samples must be at least {MINIMUM_TRAINING_WINDOWS}."
            )
        if self.abnormal_samples < 0:
            raise ValueError("abnormal_samples cannot be negative.")
        if self.noise_fraction < 0:
            raise ValueError("noise_fraction cannot be negative.")
        if self.abnormal_multiplier <= 1:
            raise ValueError("abnormal_multiplier must be greater than 1.")
        if self.min_reference_observations < 1:
            raise ValueError("min_reference_observations must be positive.")


@dataclass(frozen=True)
class ExperimentSample:
    sample_id: str
    provenance: str
    label: str
    window: BehaviorWindow


@dataclass(frozen=True)
class SyntheticExperimentModel:
    bundle: dict[str, Any]
    model_version: str
    artifact_dir: Path


@dataclass(frozen=True)
class BehaviorRiskConfig:
    """Experimental design parameters for the independent 0-100 risk score."""

    deviation_cap: float = 10.0
    deviation_scale: float = 1.0
    minimum_scored_features: int = 2
    group_weights: tuple[tuple[str, float], ...] = (
        ("overall_activity", 0.25),
        ("authentication", 0.25),
        ("process_activity", 0.35),
        ("time_of_day", 0.15),
    )

    def __post_init__(self) -> None:
        if self.deviation_cap <= 0 or self.deviation_scale <= 0:
            raise ValueError("Risk deviation cap and scale must be positive.")
        if self.minimum_scored_features < 1:
            raise ValueError("At least one scorable feature is required.")
        if any(weight < 0 for _, weight in self.group_weights):
            raise ValueError("Risk group weights cannot be negative.")
        if not math.isclose(sum(weight for _, weight in self.group_weights), 1.0):
            raise ValueError("Risk group weights must sum to 1.")


RISK_FEATURE_GROUPS = {
    "overall_activity": (
        "total_activity_count",
        "number_of_categories_active",
    ),
    "authentication": (
        "successful_login_count",
        "failed_login_count",
        "login_failure_ratio",
        "unique_login_hours",
        "logoff_count",
    ),
    "process_activity": (
        "process_count",
        "unique_process_count",
        "process_activity_frequency",
    ),
    "time_of_day": (
        "distinct_active_hours",
        "off_hours_activity_count",
    ),
}


def build_reference_profile(
    real_windows: list[BehaviorWindow],
    config: BehaviorRiskConfig | None = None,
) -> dict[str, Any]:
    """Build statistics and normalized weights from real windows only."""
    config = config or BehaviorRiskConfig()
    if not real_windows:
        raise ValueError("At least one real window is required for a reference profile.")
    if any(window.feature_names != real_windows[0].feature_names for window in real_windows):
        raise ValueError("Reference windows must have identical feature sets.")

    feature_stats: dict[str, dict[str, float | int | None]] = {}
    for name in real_windows[0].feature_names:
        values = [
            float(window.features[name])
            for window in real_windows
            if name in window.features and math.isfinite(float(window.features[name]))
        ]
        if not values:
            continue
        ordered = sorted(values)
        q1 = ordered[len(ordered) // 4]
        q3 = ordered[(3 * len(ordered)) // 4]
        med = median(values)
        deviations = [abs(value - med) for value in values]
        feature_stats[name] = {
            "median": med,
            "mad": median(deviations),
            "iqr": q3 - q1,
            "std": pstdev(values) if len(values) > 1 else 0.0,
            "observations": len(values),
        }

    configured_weights = dict(config.group_weights)
    eligible_groups = {
        group: [
            name for name in names
            if name in feature_stats
            and feature_stats[name]["observations"] >= MIN_REFERENCE_OBSERVATIONS
        ]
        for group, names in RISK_FEATURE_GROUPS.items()
    }
    eligible_groups = {group: names for group, names in eligible_groups.items() if names}
    group_weight_total = sum(configured_weights[group] for group in eligible_groups)
    if group_weight_total <= 0:
        raise ValueError("No configured risk-weight group has supported reference features.")

    feature_weights: dict[str, float] = {}
    effective_group_weights: dict[str, float] = {}
    for group, names in eligible_groups.items():
        group_weight = configured_weights[group] / group_weight_total
        effective_group_weights[group] = group_weight
        per_feature_weight = group_weight / len(names)
        feature_weights.update({name: per_feature_weight for name in names})

    return {
        "score_method_version": RISK_SCORE_METHOD_VERSION,
        "reference_window_count": len(real_windows),
        "reference_confidence": (
            "very_low" if len(real_windows) < MINIMUM_TRAINING_WINDOWS else "experimental"
        ),
        "features": feature_stats,
        "feature_weights": feature_weights,
        "group_weights": effective_group_weights,
        "configured_group_weights": configured_weights,
        "deviation_cap": config.deviation_cap,
        "deviation_scale": config.deviation_scale,
        "minimum_scored_features": config.minimum_scored_features,
        "zero_mad_fallback": (
            "Use IQR/1.349, then population standard deviation. "
            "If both are zero, score an exact median match as zero deviation; "
            "otherwise exclude the feature as unscorable."
        ),
    }


def calculate_behavior_risk_score(
    features: dict[str, float],
    reference_profile: dict[str, Any],
) -> dict[str, Any]:
    """Calculate an independent, reference-relative behaviour risk score."""
    cap = float(reference_profile["deviation_cap"])
    scale = float(reference_profile["deviation_scale"])
    weights = reference_profile["feature_weights"]
    scored: list[dict[str, Any]] = []
    excluded: dict[str, str] = {}

    for name, weight in weights.items():
        observed = features.get(name)
        stats = reference_profile["features"].get(name)
        if observed is None or not math.isfinite(float(observed)):
            excluded[name] = "missing_or_non_finite"
            continue
        if stats is None:
            excluded[name] = "missing_reference_statistics"
            continue

        observed_value = float(observed)
        reference_median = float(stats["median"])
        mad = float(stats["mad"])
        fallback_scale: float | None = None
        if mad > 0:
            denominator = 1.4826 * mad
        elif observed_value == reference_median:
            denominator = None
        else:
            iqr = float(stats["iqr"] or 0)
            standard_deviation = float(stats["std"] or 0)
            if iqr > 0:
                fallback_scale = iqr / 1.349
            elif standard_deviation > 0:
                fallback_scale = standard_deviation
            if fallback_scale is None:
                excluded[name] = "zero_variance_without_fallback_scale"
                continue
            denominator = fallback_scale

        robust_z = 0.0 if denominator is None else abs(observed_value - reference_median) / denominator
        capped = min(cap, robust_z)
        scored.append(
            {
                "feature": name,
                "observed": round(observed_value, 6),
                "reference_median": round(reference_median, 6),
                "robust_deviation": round(robust_z, 6),
                "capped_deviation": round(capped, 6),
                "weight": float(weight),
                "direction": "above" if observed_value > reference_median else "below",
                "fallback_scale": fallback_scale,
            }
        )

    if len(scored) < int(reference_profile["minimum_scored_features"]):
        return {
            "behavior_risk_score": None,
            "behavior_risk_status": "unavailable",
            "scored_feature_count": len(scored),
            "excluded_features": excluded,
            "top_features": [],
            "score_explanation": "Insufficient supported features were scorable.",
            "score_method_version": reference_profile["score_method_version"],
            "reference_confidence": reference_profile["reference_confidence"],
        }

    total_weight = sum(item["weight"] for item in scored)
    weighted_mean = sum(item["weight"] * item["capped_deviation"] for item in scored) / total_weight
    normalized_distance = weighted_mean / scale
    risk_score = max(0.0, min(100.0, 100.0 * (1.0 - math.exp(-normalized_distance))))
    scored.sort(key=lambda item: (-item["weight"] * item["capped_deviation"], item["feature"]))
    top_features = scored[:3]
    explanation = "; ".join(
        f"{item['feature']} is {item['direction']} the real-source reference median "
        f"(robust deviation {item['robust_deviation']:.3f})"
        for item in top_features
        if item["robust_deviation"] > 0
    ) or "Observed features match the real-source reference medians."
    return {
        "behavior_risk_score": round(risk_score, 6),
        "behavior_risk_status": (
            "low_confidence"
            if reference_profile["reference_confidence"] == "very_low"
            else "available"
        ),
        "scored_feature_count": len(scored),
        "excluded_features": excluded,
        "top_features": top_features,
        "score_explanation": explanation,
        "weighted_mean_deviation": round(weighted_mean, 6),
        "normalized_distance": round(normalized_distance, 6),
        "score_method_version": reference_profile["score_method_version"],
        "reference_confidence": reference_profile["reference_confidence"],
    }


def _parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_csv_backed_events(
    csv_path: Path,
    database_path: Path,
) -> list[dict[str, Any]]:
    """Join exported source IDs to normalized database rows without writes."""
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != REQUIRED_CSV_COLUMNS:
            raise ValueError("CSV columns do not match the UBADS export schema.")
        csv_rows = list(reader)

    source_ids = [int(row["source_event_id"]) for row in csv_rows]
    if len(source_ids) != len(set(source_ids)):
        raise ValueError("CSV contains duplicate source_event_id values.")

    uri = f"file:{database_path.resolve().as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as connection:
        connection.row_factory = sqlite3.Row
        placeholders = ",".join("?" for _ in source_ids)
        source_rows = [
            dict(row)
            for row in connection.execute(
                f"SELECT * FROM events WHERE id IN ({placeholders})", source_ids
            )
        ]

    by_id = {int(row["id"]): row for row in source_rows}
    if set(source_ids) != set(by_id):
        raise ValueError("CSV contains a source_event_id missing from the database.")

    events: list[dict[str, Any]] = []
    for csv_row in csv_rows:
        source = by_id[int(csv_row["source_event_id"])]
        if str(source["event_uid"]) != csv_row["event_uid"]:
            raise ValueError("CSV event_uid does not match the source database.")
        event = dict(source)
        timestamp = _parse_timestamp(event.get("timestamp_utc"))
        if timestamp is None:
            raise ValueError("Source event contains an invalid timestamp.")
        event["timestamp_utc"] = timestamp.isoformat()
        events.append(event)
    return events


def build_real_baseline_report(
    events: list[dict[str, Any]],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Extract windows in memory and summarize real-source readiness."""
    report: dict[str, Any] = {
        "provenance": REAL_PROVENANCE,
        "event_count": len(events),
        "minimum_training_windows": MINIMUM_TRAINING_WINDOWS,
        "window_sizes": {},
    }
    for window_size in ("hourly", "daily"):
        windows = extract_behavior_windows(
            events,
            window_size=window_size,
            now=now,
            include_incomplete=False,
        )
        profiles: Counter[tuple[str, str]] = Counter(
            (window.endpoint_id, window.user_id) for window in windows
        )
        report["window_sizes"][window_size] = {
            "window_count": len(windows),
            "profile_count": len(profiles),
            "profiles_meeting_minimum": sum(
                count >= MINIMUM_TRAINING_WINDOWS for count in profiles.values()
            ),
            "profile_window_counts": {
                f"{endpoint}:{user}": count
                for (endpoint, user), count in profiles.items()
            },
            "feature_names": list(windows[0].feature_names) if windows else [],
        }
    return report


def _safe_feature_value(name: str, value: float) -> float:
    if not math.isfinite(value):
        raise ValueError(f"Feature {name} has a non-finite reference value.")
    if name.endswith("_ratio"):
        return min(1.0, max(0.0, value))
    if name in {"number_of_categories_active"}:
        return min(5.0, max(0.0, round(value)))
    if name in {
        "total_activity_count",
        "successful_login_count",
        "failed_login_count",
        "unique_login_hours",
        "logoff_count",
        "files_accessed",
        "files_deleted",
        "files_handle_requested",
        "unique_file_extensions",
        "unique_directories",
        "process_count",
        "unique_process_count",
        "device_event_count",
        "unique_devices",
        "new_device_count",
        "download_related_event_count",
        "download_related_file_count",
        "distinct_active_hours",
        "off_hours_activity_count",
    }:
        return max(0.0, round(value))
    return max(0.0, value)


def _repair_relationships(features: dict[str, float]) -> None:
    if "total_activity_count" in features:
        category_counts = [
            features[name]
            for name in (
                "successful_login_count",
                "failed_login_count",
                "logoff_count",
                "file_activity_count",
                "process_count",
                "device_event_count",
                "download_related_event_count",
            )
            if name in features
        ]
        if category_counts:
            features["total_activity_count"] = max(
                features["total_activity_count"], max(category_counts)
            )
    if "unique_process_count" in features and "process_count" in features:
        features["unique_process_count"] = min(
            features["unique_process_count"], features["process_count"]
        )
    if "off_hours_activity_count" in features and "total_activity_count" in features:
        features["off_hours_activity_count"] = min(
            features["off_hours_activity_count"], features["total_activity_count"]
        )
    if "distinct_active_hours" in features:
        features["distinct_active_hours"] = min(24.0, features["distinct_active_hours"])
    if "successful_login_count" in features and "failed_login_count" in features:
        attempts = features["successful_login_count"] + features["failed_login_count"]
        if "login_failure_ratio" in features:
            features["login_failure_ratio"] = (
                features["failed_login_count"] / attempts if attempts else 0.0
            )
    for unique_name, total_name in (
        ("unique_file_extensions", "file_activity_count"),
        ("unique_directories", "file_activity_count"),
        ("unique_devices", "device_event_count"),
        ("new_device_count", "unique_devices"),
        ("download_related_file_count", "download_related_event_count"),
    ):
        if unique_name in features and total_name in features:
            features[unique_name] = min(features[unique_name], features[total_name])


def _reference_feature_names(
    windows: list[BehaviorWindow],
    minimum_observations: int,
) -> tuple[tuple[str, ...], dict[str, str]]:
    names = windows[0].feature_names
    reasons: dict[str, str] = {}
    usable: list[str] = []
    for name in names:
        values = [window.features.get(name) for window in windows]
        finite = [value for value in values if value is not None and math.isfinite(value)]
        if len(finite) < minimum_observations:
            reasons[name] = (
                f"excluded: {len(finite)} finite observations; "
                f"{minimum_observations} required"
            )
            continue
        usable.append(name)
    return tuple(usable), reasons


def generate_synthetic_samples(
    real_windows: list[BehaviorWindow],
    config: SyntheticGenerationConfig | None = None,
) -> tuple[list[ExperimentSample], dict[str, Any]]:
    """Generate labelled synthetic windows from real-window references only."""
    config = config or SyntheticGenerationConfig()
    if not real_windows:
        raise ValueError("At least one real behavioral window is required.")
    if any(window.feature_names != real_windows[0].feature_names for window in real_windows):
        raise ValueError("Real reference windows must have identical feature sets.")

    feature_names, excluded = _reference_feature_names(
        real_windows, config.min_reference_observations
    )
    if not feature_names:
        raise ValueError("No feature has enough real observations for generation.")

    rng = random.Random(config.seed)
    normal: list[ExperimentSample] = []
    abnormal: list[ExperimentSample] = []
    for index in range(config.normal_samples + config.abnormal_samples):
        base = real_windows[rng.randrange(len(real_windows))]
        features: dict[str, float] = {}
        for name in feature_names:
            base_value = float(base.features[name])
            scale = max(abs(base_value) * config.noise_fraction, 0.1)
            features[name] = _safe_feature_value(
                name,
                base_value + rng.gauss(0.0, scale),
            )
        _repair_relationships(features)
        timestamp = base.window_start + timedelta(days=index + 1)
        synthetic_window = BehaviorWindow(
            endpoint_id=base.endpoint_id,
            profile_id=base.profile_id,
            user_id=base.user_id,
            username=base.username,
            window_start=timestamp,
            window_end=timestamp + (base.window_end - base.window_start),
            window_size=base.window_size,
            features=features,
            feature_names=feature_names,
        )
        if index >= config.normal_samples:
            abnormal_features = dict(features)
            candidates = [
                name
                for name in (
                    "process_count",
                    "unique_process_count",
                    "off_hours_activity_count",
                    "total_activity_count",
                )
                if name in abnormal_features
            ]
            if not candidates:
                raise ValueError("No supported feature is available for abnormal perturbation.")
            target = candidates[index % len(candidates)]
            abnormal_features[target] = _safe_feature_value(
                target, abnormal_features[target] * config.abnormal_multiplier + 1
            )
            _repair_relationships(abnormal_features)
            synthetic_window = BehaviorWindow(
                **{**synthetic_window.__dict__, "features": abnormal_features}
            )
            abnormal.append(
                ExperimentSample(
                    sample_id=f"synthetic-abnormal-{len(abnormal):04d}",
                    provenance=SYNTHETIC_ABNORMAL_PROVENANCE,
                    label=SYNTHETIC_ABNORMAL_PROVENANCE,
                    window=synthetic_window,
                )
            )
        else:
            normal.append(
                ExperimentSample(
                    sample_id=f"synthetic-normal-{len(normal):04d}",
                    provenance=SYNTHETIC_NORMAL_PROVENANCE,
                    label=SYNTHETIC_NORMAL_PROVENANCE,
                    window=synthetic_window,
                )
            )

    metadata = {
        "seed": config.seed,
        "normal_samples": len(normal),
        "abnormal_samples": len(abnormal),
        "noise_fraction": config.noise_fraction,
        "abnormal_multiplier": config.abnormal_multiplier,
        "reference_window_count": len(real_windows),
        "reference_feature_names": list(real_windows[0].feature_names),
        "generated_feature_names": list(feature_names),
        "excluded_features": excluded,
        "reference_confidence": (
            "very_low"
            if len(real_windows) < MINIMUM_TRAINING_WINDOWS
            else "experimental"
        ),
        "unsupported_features_not_generated": [
            "network_activity",
            "confirmed_downloads",
            "session_identifiers",
        ],
    }
    return normal + abnormal, metadata


def fit_synthetic_experiment(
    samples: Iterable[ExperimentSample],
    artifact_dir: Path,
) -> SyntheticExperimentModel:
    """Fit only synthetic-normal samples in a dedicated artifact directory."""
    normal_windows = [
        sample.window
        for sample in samples
        if sample.provenance == SYNTHETIC_NORMAL_PROVENANCE
    ]
    if not normal_windows:
        raise InsufficientTrainingData("No synthetic-normal training samples were provided.")
    metadata = fit_profile_model(
        normal_windows,
        artifact_dir=artifact_dir,
        training_data_source="synthetic-demo",
    )
    bundle = load_profile_model(artifact_dir, normal_windows[0].profile_id)
    if bundle is None:
        raise RuntimeError("Synthetic model artifact could not be reloaded.")
    return SyntheticExperimentModel(
        bundle=bundle,
        model_version=f"{SYNTHETIC_MODEL_VERSION_PREFIX}{metadata['model_version']}",
        artifact_dir=artifact_dir,
    )


def score_experiment_samples(
    samples: Iterable[ExperimentSample],
    model: SyntheticExperimentModel,
    reference_profile: dict[str, Any],
) -> list[dict[str, Any]]:
    """Score samples with the existing scorer and attach provenance metadata."""
    results: list[dict[str, Any]] = []
    for sample in samples:
        result = score_behavior_window(sample.window, model.bundle)
        risk = calculate_behavior_risk_score(sample.window.features, reference_profile)
        results.append(
            {
                "sample_id": sample.sample_id,
                "features": dict(sample.window.features),
                "synthetic_behavior_type": sample.label,
                "data_provenance": sample.provenance,
                "behavior_risk_score": risk["behavior_risk_score"],
                "behavior_risk_status": risk["behavior_risk_status"],
                "model_version": model.model_version,
                "isolation_forest_score": result["isolation_forest_score"],
                "profile_deviation_score": result["profile_deviation_score"],
                "anomaly_score": result["anomaly_score"],
                "anomaly_decision": result["is_anomaly"],
                "severity": result["severity"],
                "features_contributing_most": risk["top_features"],
                "score_explanation": risk["score_explanation"],
                "behavior_risk_excluded_features": risk["excluded_features"],
                "score_method_version": risk["score_method_version"],
                "reference_confidence": risk["reference_confidence"],
                "reference_window_count": reference_profile["reference_window_count"],
            }
        )
    return results


def write_scored_experiment_outputs(
    source_csv_path: Path,
    database_path: Path,
    output_csv_path: Path,
    summary_path: Path,
    *,
    config: SyntheticGenerationConfig | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Generate isolated synthetic scores and persist only experimental outputs."""
    events = load_csv_backed_events(source_csv_path, database_path)
    real_windows = extract_behavior_windows(
        events,
        window_size="hourly",
        now=now,
        include_incomplete=False,
    )
    if not real_windows:
        raise ValueError("No eligible real hourly windows are available.")
    reference_profile = build_reference_profile(real_windows)
    samples, generation_metadata = generate_synthetic_samples(real_windows, config)

    import tempfile

    with tempfile.TemporaryDirectory(prefix="ubads-synthetic-risk-") as directory:
        model = fit_synthetic_experiment(samples, Path(directory))
        scored = score_experiment_samples(samples, model, reference_profile)

    feature_names = list(real_windows[0].feature_names)
    columns = [
        "sample_id",
        *feature_names,
        "synthetic_behavior_type",
        "data_provenance",
        "behavior_risk_score",
        "behavior_risk_status",
        "behavior_risk_excluded_features",
        "isolation_forest_score",
        "profile_deviation_score",
        "anomaly_score",
        "anomaly_decision",
        "severity",
        "features_contributing_most",
        "score_explanation",
        "model_version",
        "score_method_version",
        "reference_confidence",
        "reference_window_count",
    ]
    output_csv_path.parent.mkdir(parents=True, exist_ok=True)
    with output_csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for result in scored:
            row = {
                column: result.get(column, "")
                for column in columns
            }
            row["behavior_risk_excluded_features"] = json.dumps(
                result["behavior_risk_excluded_features"], sort_keys=True
            )
            row["features_contributing_most"] = json.dumps(
                result["features_contributing_most"], sort_keys=True
            )
            for name in feature_names:
                row[name] = result["features"][name]
            writer.writerow(row)

    available_scores = [
        float(result["behavior_risk_score"])
        for result in scored
        if result["behavior_risk_score"] is not None
    ]
    by_label: dict[str, list[float]] = {}
    for result in scored:
        if result["behavior_risk_score"] is not None:
            by_label.setdefault(result["synthetic_behavior_type"], []).append(
                float(result["behavior_risk_score"])
            )
    distribution = {
        label: {
            "count": len(values),
            "minimum": min(values) if values else None,
            "maximum": max(values) if values else None,
            "mean": sum(values) / len(values) if values else None,
        }
        for label, values in by_label.items()
    }
    summary_path.write_text(
        f"""# UBADS Synthetic Behaviour Risk Scoring Summary

- Experimental output only; not a production model or attack probability.
- Real-source reference windows: **{len(real_windows)}**
- Generated samples: **{len(samples)}**
- Scored samples: **{len(scored)}**
- Unavailable behaviour risk scores: **{sum(result['behavior_risk_score'] is None for result in scored)}**
- Reference confidence: **{reference_profile['reference_confidence']}**
- Score method version: **{reference_profile['score_method_version']}**
- Seed: **{generation_metadata['seed']}**

## Score distribution

```json
{json.dumps(distribution, indent=2)}
```

## Feature weights

```json
{json.dumps(reference_profile['group_weights'], indent=2, sort_keys=True)}
```

Feature weights are experimental design choices, normalized across supported
eligible groups. Overall activity and authentication receive 0.25 each,
process activity receives 0.35 because it dominates the available observed
events, and time-of-day receives 0.15. File, device, download, and network
weights are not invented because the reference profile does not support them.

## Formula

For each scorable feature:

`robust_z = abs(observed - median) / (1.4826 * MAD)`

Extreme deviations are capped at `{reference_profile['deviation_cap']}`.
The score is:

`D = weighted_mean(capped_robust_deviations) / {reference_profile['deviation_scale']}`

`behavior_risk_score = 100 * (1 - exp(-D))`

For zero MAD, an IQR/1.349 scale is attempted, followed by population
standard deviation. A non-median value with no positive fallback scale is
marked unscorable. An exact median match receives zero deviation.

The score is reference-relative and independent of synthetic labels,
Isolation Forest decisions, and severity thresholds.

## Limitations

Only two real hourly windows are available, so the reference confidence is
very low. Synthetic results are useful for pipeline testing only and must not
be reported as real-world accuracy or used to replace the production model.
""",
        encoding="utf-8",
    )
    return {
        "reference_profile": reference_profile,
        "generation_metadata": generation_metadata,
        "scored_samples": scored,
        "output_csv": str(output_csv_path),
        "summary_path": str(summary_path),
    }


def evaluate_synthetic_scores(results: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Compute metrics only for explicitly labelled synthetic samples."""
    rows = list(results)
    labelled = [
        row
        for row in rows
        if row.get("synthetic_behavior_type")
        in {SYNTHETIC_NORMAL_PROVENANCE, SYNTHETIC_ABNORMAL_PROVENANCE}
    ]
    actual = [
        row["synthetic_behavior_type"] == SYNTHETIC_ABNORMAL_PROVENANCE
        for row in labelled
    ]
    predicted = [bool(row["anomaly_decision"]) for row in labelled]
    tp = sum(a and p for a, p in zip(actual, predicted))
    tn = sum(not a and not p for a, p in zip(actual, predicted))
    fp = sum(not a and p for a, p in zip(actual, predicted))
    fn = sum(a and not p for a, p in zip(actual, predicted))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "sample_count": len(labelled),
        "confusion_matrix": {"true_positive": tp, "true_negative": tn, "false_positive": fp, "false_negative": fn},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "real_world_performance_claim": False,
    }
