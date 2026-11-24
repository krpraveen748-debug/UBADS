"""Read-only access to isolated synthetic experiment results."""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from statistics import mean
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SCORED_CSV = PROJECT_ROOT / "data" / "processed" / "ubads_synthetic_scored.csv"
EXPERIMENTAL_PROVENANCE = {"synthetic_normal", "synthetic_abnormal"}


def _read_rows() -> tuple[list[str], list[dict[str, str]]]:
    if not SCORED_CSV.exists():
        raise FileNotFoundError(f"Synthetic scored output not found: {SCORED_CSV}")
    with SCORED_CSV.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def get_summary() -> dict[str, Any]:
    columns, rows = _read_rows()
    labels = Counter(row.get("synthetic_behavior_type", "") for row in rows)
    available = [
        float(row["behavior_risk_score"])
        for row in rows
        if row.get("behavior_risk_score") not in ("", None)
    ]
    model_versions = sorted({row.get("model_version", "") for row in rows if row.get("model_version")})
    reference_window_count = int(rows[0]["reference_window_count"]) if rows and rows[0].get("reference_window_count") else 0
    return {
        "experimental": True,
        "provenance": "synthetic_experiment_only",
        "columns": columns,
        "reference_window_count": reference_window_count,
        "sample_count": len(rows),
        "synthetic_normal_count": labels.get("synthetic_normal", 0),
        "synthetic_abnormal_count": labels.get("synthetic_abnormal", 0),
        "scored_count": len(available),
        "unavailable_score_count": len(rows) - len(available),
        "behavior_risk_score": {
            "minimum": min(available) if available else None,
            "maximum": max(available) if available else None,
            "mean": mean(available) if available else None,
        },
        "model_versions": model_versions,
        "reference_confidence": sorted(
            {row.get("reference_confidence", "") for row in rows if row.get("reference_confidence")}
        ),
    }


def get_samples(limit: int = 100, offset: int = 0) -> dict[str, Any]:
    columns, rows = _read_rows()
    selected = rows[offset : offset + limit]
    for row in selected:
        for field in (
            "features",
            "behavior_risk_excluded_features",
            "features_contributing_most",
        ):
            if field in row:
                try:
                    row[field] = json.loads(row[field])
                except json.JSONDecodeError:
                    row[field] = []
    return {
        "experimental": True,
        "provenance": "synthetic_experiment_only",
        "columns": columns,
        "items": selected,
        "total": len(rows),
        "limit": limit,
        "offset": offset,
    }
