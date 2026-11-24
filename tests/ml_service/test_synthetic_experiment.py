from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from anomaly_detection import BehaviorWindow, InsufficientTrainingData, fit_profile_model
from synthetic_experiment import (
    SYNTHETIC_ABNORMAL_PROVENANCE,
    SYNTHETIC_MODEL_VERSION_PREFIX,
    SYNTHETIC_NORMAL_PROVENANCE,
    SyntheticGenerationConfig,
    build_reference_profile,
    build_real_baseline_report,
    calculate_behavior_risk_score,
    fit_synthetic_experiment,
    generate_synthetic_samples,
    score_experiment_samples,
)


FEATURES = (
    "total_activity_count",
    "number_of_categories_active",
    "distinct_active_hours",
    "off_hours_activity_count",
    "process_count",
    "unique_process_count",
)


def _window(day: int, values: tuple[float, ...]) -> BehaviorWindow:
    start = datetime(2026, 1, 1 + day, 10, tzinfo=timezone.utc)
    return BehaviorWindow(
        endpoint_id="endpoint-a",
        profile_id="a" * 32,
        user_id="user-a",
        username="user-a",
        window_start=start,
        window_end=start + timedelta(hours=1),
        window_size="hourly",
        features=dict(zip(FEATURES, values)),
        feature_names=FEATURES,
    )


def _reference_windows() -> list[BehaviorWindow]:
    return [
        _window(0, (5, 1, 2, 1, 4, 2)),
        _window(1, (8, 1, 3, 2, 7, 3)),
    ]


def test_real_baseline_reports_insufficient_profiles():
    report = build_real_baseline_report([], now=datetime(2026, 3, 1, tzinfo=timezone.utc))
    assert report["provenance"] == "real-source"
    assert report["event_count"] == 0
    assert report["minimum_training_windows"] == 20


def test_synthetic_generation_is_reproducible_and_provenance_separated():
    config = SyntheticGenerationConfig(seed=7, normal_samples=20, abnormal_samples=4)
    first, first_metadata = generate_synthetic_samples(_reference_windows(), config)
    second, second_metadata = generate_synthetic_samples(_reference_windows(), config)

    assert first_metadata == second_metadata
    assert [
        (sample.sample_id, sample.provenance, sample.window.features)
        for sample in first
    ] == [
        (sample.sample_id, sample.provenance, sample.window.features)
        for sample in second
    ]
    assert {sample.provenance for sample in first} == {
        SYNTHETIC_NORMAL_PROVENANCE,
        SYNTHETIC_ABNORMAL_PROVENANCE,
    }
    assert all(sample.provenance != "real-source" for sample in first)
    assert all(value >= 0 for sample in first for value in sample.window.features.values())
    assert all(
        sample.window.features["number_of_categories_active"] <= 5
        for sample in first
    )


def test_sparse_features_are_excluded_and_unsupported_features_are_not_created():
    sparse = [
        _window(0, (5, 1, 2, 1, 4, 2)),
        BehaviorWindow(
            **{
                **_window(1, (8, 1, 3, 2, 7, 3)).__dict__,
                "features": {
                    "total_activity_count": 8,
                    "number_of_categories_active": 1,
                    "distinct_active_hours": 3,
                    "off_hours_activity_count": 2,
                    "process_count": 7,
                },
            }
        ),
    ]
    _, metadata = generate_synthetic_samples(
        sparse,
        SyntheticGenerationConfig(seed=1, normal_samples=20, abnormal_samples=0),
    )
    assert "unique_process_count" in metadata["excluded_features"]
    assert "network_activity" in metadata["unsupported_features_not_generated"]


def test_real_training_still_rejects_insufficient_windows(tmp_path):
    with pytest.raises(InsufficientTrainingData):
        fit_profile_model([_reference_windows()[0]], artifact_dir=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_synthetic_model_uses_separate_artifacts_and_score_metadata(tmp_path):
    samples, _ = generate_synthetic_samples(
        _reference_windows(),
        SyntheticGenerationConfig(seed=3, normal_samples=20, abnormal_samples=2),
    )
    reference_profile = build_reference_profile(_reference_windows())
    model = fit_synthetic_experiment(samples, tmp_path / "synthetic-model")
    assert model.model_version.startswith(SYNTHETIC_MODEL_VERSION_PREFIX)
    assert model.bundle["metadata"]["training_data_source"] == "synthetic-demo"
    assert model.bundle["metadata"]["training_windows"] == 20

    results = score_experiment_samples(samples[:2], model, reference_profile)
    assert len(results) == 2
    assert all(result["data_provenance"] == SYNTHETIC_NORMAL_PROVENANCE for result in results)
    assert all(result["model_version"].startswith(SYNTHETIC_MODEL_VERSION_PREFIX) for result in results)
    assert all(result["profile_deviation_score"] is not None for result in results)
    assert all(result["features"] for result in results)
    assert all(result["behavior_risk_status"] == "low_confidence" for result in results)
    assert all(0 <= result["behavior_risk_score"] <= 100 for result in results)


def test_behavior_risk_score_is_label_independent_and_reproducible():
    profile = build_reference_profile(_reference_windows())
    features = {"total_activity_count": 12, "process_count": 11, "unique_process_count": 5}
    first = calculate_behavior_risk_score(features, profile)
    second = calculate_behavior_risk_score(features, profile)
    assert first == second
    assert 0 <= first["behavior_risk_score"] <= 100
    higher = calculate_behavior_risk_score(
        {**features, "process_count": 50},
        profile,
    )
    assert higher["behavior_risk_score"] > first["behavior_risk_score"]


def test_behavior_risk_score_reports_zero_mad_and_unscorable_features():
    profile = build_reference_profile(_reference_windows())
    profile["features"]["total_activity_count"].update({"mad": 0.0, "iqr": 0.0, "std": 0.0})
    unchanged = calculate_behavior_risk_score({"total_activity_count": 5}, profile)
    assert unchanged["behavior_risk_score"] is None
    assert unchanged["behavior_risk_status"] == "unavailable"
    assert "process_count" in unchanged["excluded_features"]
