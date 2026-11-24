from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from anomaly_detection import (
    InsufficientTrainingData,
    extract_behavior_windows,
    fit_profile_model,
    load_profile_model,
    model_is_stale,
    score_behavior_window,
)


USER_SID = "S-1-5-21-111-222-333-1001"


def _event(endpoint_id, timestamp, *, user_sid=USER_SID, username="synthetic.user", **overrides):
    event = {
        "endpoint_id": endpoint_id,
        "event_id": 4688,
        "event_type": "process_created",
        "event_category": "process_activity",
        "timestamp_utc": timestamp.isoformat() if isinstance(timestamp, datetime) else timestamp,
        "username": username,
        "domain": "SYNTHETIC",
        "user_sid": user_sid,
        "account_type": "human_or_unknown",
        "process_name": "notepad.exe",
        "process_id": "100",
    }
    event.update(overrides)
    return event


def _synthetic_training_events():
    start = datetime(2026, 1, 1, 10, tzinfo=timezone.utc)
    events = []
    for day in range(40):
        current = start + timedelta(days=day)
        events.extend(
            _event("endpoint-a", current + timedelta(minutes=index), process_name=f"normal-{index % 2}.exe")
            for index in range(2 + day % 4)
        )
        events.append(
            _event(
                "endpoint-a",
                current + timedelta(minutes=10),
                event_id=4624,
                event_type="successful_logon",
                event_category="authentication",
                process_name=None,
            )
        )
    return events


def test_extract_behavior_windows_isolates_endpoint_and_user_and_ignores_invalid_events():
    events = _synthetic_training_events()[:3]
    same_user_other_endpoint = _event("endpoint-b", datetime(2026, 1, 1, 11, tzinfo=timezone.utc))
    service_account = _event(
        "endpoint-a",
        datetime(2026, 1, 1, 12, tzinfo=timezone.utc),
        username="SYSTEM",
        account_type="system",
    )
    no_endpoint = _event(None, datetime(2026, 1, 1, 13, tzinfo=timezone.utc))
    invalid_timestamp = _event("endpoint-a", "not-a-timestamp")

    windows = extract_behavior_windows(
        events + [same_user_other_endpoint, service_account, no_endpoint, invalid_timestamp],
        now=datetime(2026, 1, 4, tzinfo=timezone.utc),
        include_incomplete=False,
    )

    assert len(windows) == 2
    assert {window.endpoint_id for window in windows} == {"endpoint-a", "endpoint-b"}
    assert len({window.profile_id for window in windows}) == 2


def test_training_requires_multiple_completed_behavior_windows(tmp_path):
    windows = extract_behavior_windows(
        _synthetic_training_events()[:3],
        now=datetime(2026, 1, 4, tzinfo=timezone.utc),
        include_incomplete=False,
    )
    with pytest.raises(InsufficientTrainingData, match="At least"):
        fit_profile_model(windows, artifact_dir=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_training_rejects_many_windows_with_no_behavioral_variation(tmp_path):
    start = datetime(2026, 1, 1, 10, tzinfo=timezone.utc)
    events = []
    for day in range(25):
        current = start + timedelta(days=day)
        events.extend(
            [
                _event("endpoint-a", current),
                _event("endpoint-a", current + timedelta(minutes=5)),
            ]
        )
    windows = extract_behavior_windows(
        events,
        now=datetime(2026, 2, 1, tzinfo=timezone.utc),
        include_incomplete=False,
    )
    with pytest.raises(InsufficientTrainingData, match="no behavioral feature variation"):
        fit_profile_model(windows, artifact_dir=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_isolation_forest_persists_and_scores_normal_and_unusual_windows(tmp_path):
    events = _synthetic_training_events()
    training = extract_behavior_windows(
        events,
        now=datetime(2026, 3, 1, tzinfo=timezone.utc),
        include_incomplete=False,
    )
    metadata = fit_profile_model(
        training,
        artifact_dir=tmp_path,
        training_data_source="synthetic-demo",
    )
    bundle = load_profile_model(tmp_path, training[0].profile_id)
    assert bundle is not None
    assert bundle["metadata"]["model_version"] == metadata["model_version"]
    assert bundle["metadata"]["training_data_source"] == "synthetic-demo"
    assert bundle["metadata"]["training_windows"] == 40

    normal_timestamp = datetime(2026, 3, 2, 10, tzinfo=timezone.utc)
    normal_events = [
        _event("endpoint-a", normal_timestamp, process_name="normal-0.exe"),
        _event("endpoint-a", normal_timestamp + timedelta(minutes=5), process_name="normal-1.exe"),
        _event(
            "endpoint-a",
            normal_timestamp + timedelta(minutes=10),
            event_id=4624,
            event_type="successful_logon",
            event_category="authentication",
            process_name=None,
        ),
    ]
    unusual_events = list(normal_events)
    unusual_events.extend(
        _event(
            "endpoint-a",
            normal_timestamp + timedelta(minutes=15 + index),
            process_name=f"unusual-{index}.exe",
            process_id=str(1000 + index),
        )
        for index in range(60)
    )
    normal_window = extract_behavior_windows(normal_events)[0]
    unusual_window = extract_behavior_windows(unusual_events)[0]
    normal_result = score_behavior_window(normal_window, bundle)
    unusual_result = score_behavior_window(unusual_window, bundle)

    assert not normal_result["is_anomaly"]
    assert unusual_result["is_anomaly"]
    assert unusual_result["anomaly_score"] > normal_result["anomaly_score"]
    assert unusual_result["features"]
    assert unusual_result["explanation_method"] == "robust_median_deviation"
    assert unusual_result["training_data_source"] == "synthetic-demo"
    assert unusual_result["model_version"] == metadata["model_version"]


def test_inference_rejects_feature_set_mismatch(tmp_path):
    windows = extract_behavior_windows(
        _synthetic_training_events(),
        now=datetime(2026, 3, 1, tzinfo=timezone.utc),
        include_incomplete=False,
    )
    fit_profile_model(windows, artifact_dir=tmp_path, training_data_source="synthetic-demo")
    bundle = load_profile_model(tmp_path, windows[0].profile_id)
    assert bundle is not None
    incomplete_window = extract_behavior_windows(
        [_event("endpoint-a", datetime(2026, 3, 2, 10, tzinfo=timezone.utc))],
    )[0]
    with pytest.raises(ValueError, match="feature set"):
        score_behavior_window(incomplete_window, bundle)


def test_model_staleness_uses_trained_at_metadata():
    now = datetime(2026, 3, 1, tzinfo=timezone.utc)
    assert not model_is_stale({"trained_at": (now - timedelta(days=1)).isoformat()}, now=now)
    assert model_is_stale({"trained_at": (now - timedelta(days=31)).isoformat()}, now=now)
    assert model_is_stale({"trained_at": "invalid"}, now=now)
