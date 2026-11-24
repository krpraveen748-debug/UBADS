"""Generate isolated synthetic experiment outputs for UBADS."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ML_SERVICE = PROJECT_ROOT / "ml-service"
if str(ML_SERVICE) not in sys.path:
    sys.path.insert(0, str(ML_SERVICE))

from synthetic_experiment import (  # noqa: E402
    SyntheticGenerationConfig,
    write_scored_experiment_outputs,
)


def main() -> None:
    result = write_scored_experiment_outputs(
        PROJECT_ROOT / "data" / "processed" / "ubads_real_dataset_500.csv",
        PROJECT_ROOT / "data" / "app.db",
        PROJECT_ROOT / "data" / "processed" / "ubads_synthetic_scored.csv",
        PROJECT_ROOT / "data" / "processed" / "ubads_synthetic_scoring_summary.md",
        config=SyntheticGenerationConfig(seed=42, normal_samples=40, abnormal_samples=20),
        now=datetime.now(timezone.utc),
    )
    print(f"Generated {len(result['scored_samples'])} scored synthetic samples.")
    print(result["output_csv"])
    print(result["summary_path"])


if __name__ == "__main__":
    main()
