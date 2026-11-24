"""Reproducible, isolated synthetic demonstration of the real ML pipeline."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from anomaly_detection import (
    extract_behavior_windows,
    fit_profile_model,
    load_profile_model,
    score_behavior_window,
)


def _event(timestamp: datetime, *, process_name: str = "notepad.exe", event_id: int = 4688):
    is_logon = event_id == 4624
    return {
        "endpoint_id": "synthetic-demo-endpoint",
        "event_id": event_id,
        "event_type": "successful_logon" if is_logon else "process_created",
        "event_category": "authentication" if is_logon else "process_activity",
        "timestamp_utc": timestamp.isoformat(),
        "username": "synthetic.demo.user",
        "domain": "SYNTHETIC",
        "user_sid": "S-1-5-21-111-222-333-1001",
        "account_type": "human_or_unknown",
        "process_name": None if is_logon else process_name,
        "process_id": "100",
    }


def main() -> None:
    start = datetime(2026, 1, 1, 10, tzinfo=timezone.utc)
    training_events = []
    for day in range(40):
        current = start + timedelta(days=day)
        training_events.extend(
            _event(current + timedelta(minutes=index), process_name=f"normal-{index % 2}.exe")
            for index in range(2 + day % 4)
        )
        training_events.append(_event(current + timedelta(minutes=10), event_id=4624))

    normal_time = start + timedelta(days=41)
    normal_events = [
        _event(normal_time, process_name="normal-0.exe"),
        _event(normal_time + timedelta(minutes=5), process_name="normal-1.exe"),
        _event(normal_time + timedelta(minutes=10), event_id=4624),
    ]
    unusual_events = list(normal_events)
    unusual_events.extend(
        _event(normal_time + timedelta(minutes=15 + index), process_name=f"unusual-{index}.exe")
        for index in range(60)
    )

    with tempfile.TemporaryDirectory(prefix="ubads-ml-demo-") as directory:
        artifact_dir = Path(directory)
        training_windows = extract_behavior_windows(
            training_events,
            now=datetime(2026, 3, 1, tzinfo=timezone.utc),
            include_incomplete=False,
        )
        metadata = fit_profile_model(
            training_windows,
            artifact_dir=artifact_dir,
            training_data_source="synthetic-demo",
        )
        bundle = load_profile_model(artifact_dir, training_windows[0].profile_id)
        assert bundle is not None
        normal_window = extract_behavior_windows(normal_events)[0]
        unusual_window = extract_behavior_windows(unusual_events)[0]
        normal = score_behavior_window(normal_window, bundle)
        unusual = score_behavior_window(unusual_window, bundle)

        print(
            json.dumps(
                {
                    "training_data_source": metadata["training_data_source"],
                    "training_windows": metadata["training_windows"],
                    "model_version": metadata["model_version"],
                    "normal_window": {
                        "score": normal["anomaly_score"],
                        "is_anomaly": normal["is_anomaly"],
                        "explanation": normal["features"],
                    },
                    "unusual_window": {
                        "score": unusual["anomaly_score"],
                        "is_anomaly": unusual["is_anomaly"],
                        "explanation": unusual["features"],
                    },
                    "note": "Synthetic-only output. Scores are not probabilities; an anomaly is not proof of an incident.",
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
