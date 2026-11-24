from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.models.anomaly import AnomalyDetection
from app.repositories.pipeline_bridge import storage
from app.services import anomaly_service
from app.services import synthetic_experiment_service


def _insert_anomaly(session, *, endpoint_id, username, score=0.93):
    row = AnomalyDetection(
        endpoint_id=endpoint_id,
        profile_id=f"profile-{endpoint_id}",
        username=username,
        window_start=datetime(2026, 2, 1, tzinfo=timezone.utc),
        window_end=datetime(2026, 2, 2, tzinfo=timezone.utc),
        window_size="daily",
        anomaly_score=score,
        severity="Medium",
        explanation_json=json.dumps(
            {
                "features": [
                    {
                        "feature": "process_count",
                        "observed": 45,
                        "baseline_median": 3,
                        "direction": "above",
                        "robust_deviation": 42,
                    }
                ],
                "method": "robust_median_deviation",
            }
        ),
        explanation_method="robust_median_deviation",
        model_version="isolation-forest-v1-test",
        training_data_source="synthetic-demo",
        detected_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        is_anomaly=True,
    )
    session.add(row)
    session.commit()
    return row


def test_anomaly_routes_require_dashboard_admin(anon_client):
    assert anon_client.get("/api/anomalies").status_code == 401
    assert anon_client.get("/api/ml/anomaly-status").status_code == 401
    assert anon_client.post("/api/ml/train-anomaly-models").status_code == 401
    assert anon_client.get("/api/ml/synthetic-experiment").status_code == 401
    assert anon_client.get("/api/ml/synthetic-experiment/samples").status_code == 401


def test_synthetic_experiment_routes_are_admin_only_and_separate(client, monkeypatch, tmp_path):
    header = (
        "sample_id,total_activity_count,synthetic_behavior_type,data_provenance,"
        "behavior_risk_score,behavior_risk_status,behavior_risk_excluded_features,"
        "isolation_forest_score,profile_deviation_score,anomaly_score,anomaly_decision,"
        "severity,features_contributing_most,score_explanation,model_version,"
        "score_method_version,reference_confidence,reference_window_count\n"
    )
    row = (
        'synthetic-normal-0000,5,synthetic_normal,synthetic_normal,10.5,low_confidence,{},'
        '0.1,0.2,0.12,False,Low,"[]",stable,synthetic-experiment/test,'
        'behavior-risk-v1,very_low,2\n'
    )
    output = tmp_path / "synthetic.csv"
    output.write_text(header + row, encoding="utf-8")
    monkeypatch.setattr(synthetic_experiment_service, "SCORED_CSV", output)

    summary = client.get("/api/ml/synthetic-experiment")
    assert summary.status_code == 200
    assert summary.json()["experimental"] is True
    assert summary.json()["reference_window_count"] == 2
    samples = client.get("/api/ml/synthetic-experiment/samples").json()
    assert samples["items"][0]["behavior_risk_score"] == "10.5"
    assert samples["items"][0]["synthetic_behavior_type"] == "synthetic_normal"


def test_anomaly_list_detail_and_filters_are_endpoint_scoped(client, test_session):
    first = _insert_anomaly(test_session, endpoint_id="endpoint-a", username="synthetic.alice")
    _insert_anomaly(test_session, endpoint_id="endpoint-b", username="synthetic.bob", score=0.98)

    all_results = client.get("/api/anomalies")
    assert all_results.status_code == 200
    body = all_results.json()
    assert body["total"] == 2
    assert body["severity_counts"] == {"Medium": 2}
    assert {item["endpoint_id"] for item in body["items"]} == {"endpoint-a", "endpoint-b"}
    assert body["items"][0]["explanation"]["features"][0]["feature"] == "process_count"

    endpoint_results = client.get("/api/anomalies", params={"endpoint_id": "endpoint-a"}).json()
    assert endpoint_results["total"] == 1
    assert endpoint_results["items"][0]["username"] == "synthetic.alice"

    detail = client.get(f"/api/anomalies/{first.id}")
    assert detail.status_code == 200
    assert detail.json()["profile_id"] == "profile-endpoint-a"
    assert client.get("/api/anomalies/9999").status_code == 404


def test_anomaly_time_filter_and_invalid_range(client, test_session):
    row = _insert_anomaly(test_session, endpoint_id="endpoint-a", username="synthetic.alice")
    in_range = client.get(
        "/api/anomalies",
        params={
            "start_time": (row.detected_at - timedelta(seconds=1)).isoformat(),
            "end_time": (row.detected_at + timedelta(seconds=1)).isoformat(),
        },
    )
    assert in_range.json()["total"] == 1
    invalid = client.get(
        "/api/anomalies",
        params={
            "start_time": (row.detected_at + timedelta(days=1)).isoformat(),
            "end_time": row.detected_at.isoformat(),
        },
    )
    assert invalid.status_code == 422


def test_model_status_and_training_use_temporary_artifact_directory(
    client, test_session, monkeypatch, tmp_path
):
    monkeypatch.setattr(settings, "anomaly_model_dir", tmp_path)
    status = client.get("/api/ml/anomaly-status")
    assert status.status_code == 200
    assert status.json()["algorithm"] == "IsolationForest"
    assert status.json()["profiles"] == []

    trained = client.post("/api/ml/train-anomaly-models")
    assert trained.status_code == 200
    assert trained.json()["training_data_source"] == "real"
    assert trained.json()["trained_profiles"] == []
    assert list(tmp_path.iterdir()) == []


def test_training_and_ingestion_inference_use_persisted_endpoint_events(
    test_session, monkeypatch, tmp_path
):
    original_fit = anomaly_service.fit_profile_model

    def fit_synthetic_profile(
        windows, *, artifact_dir=None, artifact_store=None, training_data_source="real"
    ):
        return original_fit(
            windows,
            artifact_dir=artifact_dir,
            artifact_store=artifact_store,
            training_data_source="synthetic-demo",
        )

    monkeypatch.setattr(settings, "anomaly_model_dir", tmp_path)
    monkeypatch.setattr(anomaly_service, "fit_profile_model", fit_synthetic_profile)
    endpoint_id = "synthetic-endpoint"
    username = "synthetic.behavior.user"
    user_sid = "S-1-5-21-111-222-333-1001"
    now = datetime.now(timezone.utc)

    def store_event(record_id, timestamp, *, event_id=4688, process_name="notepad.exe"):
        is_logon = event_id == 4624
        storage.insert_event(
            test_session,
            {
                "event_id": event_id,
                "event_record_id": record_id,
                "event_type": "successful_logon" if is_logon else "process_created",
                "event_category": "authentication" if is_logon else "process_activity",
                "timestamp": timestamp.isoformat(),
                "computer_name": "SYNTHETIC-TEST-PC",
                "username": username,
                "domain": "SYNTHETIC",
                "user_sid": user_sid,
                "account_type": "human_or_unknown",
                "process_name": None if is_logon else process_name,
                "process_id": record_id,
                "raw_event_data": {},
            },
            log_name="Security",
            endpoint_id=endpoint_id,
        )

    for day in range(25, 1, -1):
        day_start = now - timedelta(days=day)
        for index in range(2 + day % 4):
            store_event(
                f"baseline-process-{day}-{index}",
                day_start.replace(hour=10, minute=index, second=0, microsecond=0),
                process_name=f"normal-{index % 2}.exe",
            )
        store_event(
            f"baseline-logon-{day}",
            day_start.replace(hour=10, minute=10, second=0, microsecond=0),
            event_id=4624,
        )

    training = anomaly_service.train_models(test_session)
    assert len(training["trained_profiles"]) == 1
    assert training["trained_profiles"][0]["training_data_source"] == "synthetic-demo"

    current_window = now.replace(hour=10, minute=0, second=0, microsecond=0)
    for index in range(60):
        store_event(
            f"current-unusual-{index}",
            current_window + timedelta(minutes=15 + index),
            process_name=f"unusual-{index}.exe",
        )
    result = anomaly_service.score_endpoint_events(test_session, endpoint_id)

    assert result["detections_recorded"] == 1
    detection = test_session.query(AnomalyDetection).one()
    assert detection.endpoint_id == endpoint_id
    assert detection.training_data_source == "synthetic-demo"
    assert detection.explanation_json
