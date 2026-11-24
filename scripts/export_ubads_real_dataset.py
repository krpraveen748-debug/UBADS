"""Export a deterministic, privacy-preserving sample of existing UBADS events.

This script never writes to the source database. It exports only supported
Windows Security events and records the provenance and derivations in a
companion README.
"""

from __future__ import annotations

import csv
import hashlib
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DATABASE = PROJECT_ROOT / "data" / "app.db"
OUTPUT_DIRECTORY = PROJECT_ROOT / "data" / "processed"
OUTPUT_CSV = OUTPUT_DIRECTORY / "ubads_real_dataset_500.csv"
OUTPUT_README = OUTPUT_DIRECTORY / "ubads_real_dataset_500_README.md"

REQUIRED_COLUMNS = [
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
]

SUPPORTED_EVENTS = {
    4624: "authentication",
    4625: "authentication",
    4634: "authentication",
    4647: "authentication",
    4656: "file_activity",
    4660: "file_activity",
    4663: "file_activity",
    4688: "process_activity",
    6416: "device_activity",
}
FEATURE_VERSION = "ubads-feature-schema-v1"
DATA_SOURCE = "windows_security_event_log"
PROVENANCE_STATUS = "likely_real_unverified_origin"
SAMPLE_SIZE = 500


def _read_only_connection(path: Path) -> sqlite3.Connection:
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    return sqlite3.connect(uri, uri=True)


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _stable_mask(value: str | None, label: str) -> str:
    if not value:
        return ""
    digest = hashlib.sha256(f"ubads-export-v1:{label}:{value}".encode("utf-8")).hexdigest()
    return f"{label}_{digest[:16]}"


def _resolve_user_id(row: dict[str, Any]) -> str:
    user_sid = row.get("user_sid")
    if user_sid:
        return str(user_sid)
    username = row.get("username")
    domain = row.get("domain")
    if username and domain:
        return f"{domain}\\{username}"
    if username:
        return str(username)
    return ""


def _evenly_spaced(rows: list[dict[str, Any]], count: int) -> list[dict[str, Any]]:
    if count >= len(rows):
        return list(rows)
    if count <= 0:
        return []
    if count == 1:
        return [rows[0]]
    indexes = {
        round(index * (len(rows) - 1) / (count - 1))
        for index in range(count)
    }
    return [rows[index] for index in sorted(indexes)]


def _load_eligible_rows() -> list[dict[str, Any]]:
    if not SOURCE_DATABASE.exists():
        raise FileNotFoundError(f"Source database not found: {SOURCE_DATABASE}")

    with _read_only_connection(SOURCE_DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        rows = [dict(row) for row in connection.execute(
            "SELECT * FROM events "
            "WHERE log_name = 'Security' AND event_id IN "
            "(4624, 4625, 4634, 4647, 4656, 4660, 4663, 4688, 6416) "
            "ORDER BY timestamp_utc, id"
        )]

    eligible: list[dict[str, Any]] = []
    for row in rows:
        if row.get("event_id") not in SUPPORTED_EVENTS:
            continue
        if not row.get("event_uid") or not row.get("timestamp_utc"):
            continue
        try:
            _parse_utc(str(row["timestamp_utc"]))
        except (TypeError, ValueError):
            continue
        row["derived_user_id"] = _resolve_user_id(row)
        eligible.append(row)
    return eligible


def _select_rows(eligible: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(eligible) < SAMPLE_SIZE:
        raise RuntimeError(
            f"Only {len(eligible)} eligible records are available; "
            f"{SAMPLE_SIZE} are required. No CSV was generated."
        )

    by_category: dict[str, list[dict[str, Any]]] = {}
    for row in eligible:
        by_category.setdefault(SUPPORTED_EVENTS[int(row["event_id"])], []).append(row)

    # Largest-remainder allocation preserves the source distribution while
    # guaranteeing representation for every available category.
    counts = {category: len(rows) for category, rows in by_category.items()}
    quotas = {category: SAMPLE_SIZE * count / len(eligible) for category, count in counts.items()}
    selected_counts = {category: int(value) for category, value in quotas.items()}
    remaining = SAMPLE_SIZE - sum(selected_counts.values())
    for category, _ in sorted(
        quotas.items(),
        key=lambda item: (-(item[1] - int(item[1])), item[0]),
    )[:remaining]:
        selected_counts[category] += 1

    selected: list[dict[str, Any]] = []
    for category in sorted(by_category):
        selected.extend(_evenly_spaced(by_category[category], selected_counts[category]))

    selected.sort(key=lambda row: (_parse_utc(str(row["timestamp_utc"])), int(row["id"])))
    if len(selected) != SAMPLE_SIZE:
        raise AssertionError(f"Deterministic selection produced {len(selected)} rows.")
    if len({row["id"] for row in selected}) != SAMPLE_SIZE:
        raise AssertionError("Selection contains duplicate source IDs.")
    if len({row["event_uid"] for row in selected}) != SAMPLE_SIZE:
        raise AssertionError("Selection contains duplicate event UIDs.")
    return selected


def _export_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_event_id": row["id"],
        "event_uid": row["event_uid"],
        "event_id": row["event_id"],
        "timestamp_utc": row["timestamp_utc"],
        "endpoint_id": row.get("endpoint_id") or "",
        "derived_user_id": _stable_mask(row.get("derived_user_id"), "user"),
        "username_masked": _stable_mask(row.get("username"), "user"),
        "computer_name_masked": _stable_mask(row.get("computer_name"), "computer"),
        "log_name": row.get("log_name") or "",
        "event_category": row.get("event_category") or "",
        "event_type": row.get("event_type") or "",
        "account_type": row.get("account_type") or "",
        "logon_type": row.get("logon_type") if row.get("logon_type") is not None else "",
        "logon_type_description": row.get("logon_type_description") or "",
        "process_name_masked": _stable_mask(row.get("process_name"), "process"),
        "parent_process_name_masked": _stable_mask(row.get("parent_process_name"), "parent_process"),
        "process_id": row.get("process_id") or "",
        "parent_process_id": row.get("parent_process_id") or "",
        "file_extension": row.get("file_extension") or "",
        "file_action": row.get("file_action") or "",
        "device_class": row.get("device_class") or "",
        "device_action": row.get("device_action") or "",
        "feature_version": FEATURE_VERSION,
        "data_source": DATA_SOURCE,
        "provenance_status": PROVENANCE_STATUS,
    }


def _write_readme(rows: list[dict[str, Any]], eligible_count: int) -> None:
    category_counts = Counter(row["event_category"] for row in rows)
    event_counts = Counter(str(row["event_id"]) for row in rows)
    endpoint_count = len({row["endpoint_id"] for row in rows if row["endpoint_id"]})
    user_count = len({row["derived_user_id"] for row in rows if row["derived_user_id"]})
    timestamps = [_parse_utc(str(row["timestamp_utc"])) for row in rows]
    missing = {
        column: sum(1 for row in rows if row[column] in ("", None))
        for column in REQUIRED_COLUMNS
    }
    file_size = OUTPUT_CSV.stat().st_size

    category_lines = "\n".join(f"- `{key}`: {value}" for key, value in sorted(category_counts.items()))
    event_lines = "\n".join(f"- `{key}`: {value}" for key, value in sorted(event_counts.items()))
    missing_lines = "\n".join(f"- `{key}`: {value}" for key, value in missing.items())

    OUTPUT_README.write_text(
        f"""# UBADS Real Event Dataset (500 Records)

## Summary

- Source: `data/app.db`
- Exported rows: **{len(rows)}**
- Eligible source rows before selection: **{eligible_count}**
- CSV size: **{file_size} bytes**
- Timestamp range: `{min(timestamps).isoformat()}` to `{max(timestamps).isoformat()}`
- Unique endpoint IDs in export: **{endpoint_count}**
- Unique masked derived users in export: **{user_count}**
- Provenance: `{PROVENANCE_STATUS}`
- Synthetic records: **0**
- Unsupported Application event ID 1001 records: **0**

## Selection method

The source database was opened read-only. Records were restricted to the
supported Windows `Security` event IDs defined by the project collector.
Rows were sorted chronologically and selected deterministically using a
largest-remainder category allocation plus evenly spaced selection within
each category. Source rows were not modified or deleted.

`derived_user_id` uses the existing UBADS resolution order
(`user_sid`, domain plus username, username) and is then stable-hashed for
privacy. Usernames, computer names, process names, and parent process names
are also stable-hashed. Missing source values remain empty.

## Category distribution

{category_lines}

## Event ID distribution

{event_lines}

## Missing values

{missing_lines}

## Provenance and limitations

The records are labelled `{PROVENANCE_STATUS}` because the database contains
collector-shaped Windows Security events, but they have not been independently
verified against Event Viewer. This CSV does not contain `raw_event_data`,
passwords, credentials, tokens, file paths, or source IP values.

This is a 500-event dataset, not 500 independent behavioral ML windows.
Current UBADS Isolation Forest training requires at least 20 completed
windows per endpoint/user profile. The export can support event-level
feature-engineering tests, but it does not by itself satisfy that window
requirement.

## ML compatibility

Derivable from this CSV: activity counts, process activity, authentication
counts, file activity, device activity, active hours, UTC off-hours counts,
unique process tokens, and unique device counts when the source fields are
present.

Not reliably derivable: destination network activity, confirmed browser
downloads, complete session identifiers, and failed-login statistics when no
failed-login events are present. Missing values must remain missing.
""",
        encoding="utf-8",
    )


def main() -> None:
    eligible = _load_eligible_rows()
    selected = _select_rows(eligible)
    exported = [_export_row(row) for row in selected]

    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=REQUIRED_COLUMNS)
        writer.writeheader()
        writer.writerows(exported)
    _write_readme(exported, len(eligible))

    print(f"Exported {len(exported)} rows to {OUTPUT_CSV}")
    print(f"Documentation written to {OUTPUT_README}")


if __name__ == "__main__":
    main()
