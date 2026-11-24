"""
Read-only fingerprint of the REAL data/app.db, to prove test runs leave it alone.

    python tests/e2e/real_db_guard.py snapshot OUT.json
    python tests/e2e/real_db_guard.py verify   OUT.json

The database is opened with SQLite's read-only URI mode, so this tool cannot
modify it. The installed agent legitimately keeps uploading events and
refreshing last_seen while tests run, so the comparison is:
  - endpoints / dashboard_users: row counts + a hash of every stable column
    (excluding last_seen / last_ingest_at, which a live agent updates);
  - events: every row that existed at snapshot time (id <= max_id) must hash
    identically; rows added afterwards are reported but expected to come only
    from the real agent.
Nothing secret is printed: hashes only.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from pathlib import Path

DB = Path(__file__).resolve().parents[2] / "data" / "app.db"
STABLE = {
    "endpoints": "select endpoint_id, display_name, operating_system, agent_version, registered_at, credential_hash, credential_issued_at from endpoints order by endpoint_id",
    "dashboard_users": "select username, password_hash, created_at, role, email, full_name, organization from dashboard_users order by username",
}


def _connect() -> sqlite3.Connection:
    return sqlite3.connect(f"file:{DB.as_posix()}?mode=ro", uri=True)


def _digest(rows) -> str:
    h = hashlib.sha256()
    for row in rows:
        h.update(repr(row).encode())
    return h.hexdigest()


def fingerprint(max_event_id: int | None = None) -> dict:
    con = _connect()
    try:
        tables = {r[0] for r in con.execute("select name from sqlite_master where type='table'")}
        out: dict = {"tables": sorted(tables)}
        for name, sql in STABLE.items():
            rows = con.execute(sql).fetchall()
            out[name] = {"count": len(rows), "sha256": _digest(rows)}
        if max_event_id is None:
            max_event_id = con.execute("select coalesce(max(id), 0) from events").fetchone()[0]
        rows = con.execute("select * from events where id <= ? order by id", (max_event_id,)).fetchall()
        out["events"] = {"max_id": max_event_id, "count_at_or_below": len(rows), "sha256": _digest(rows)}
        out["events_total_now"] = con.execute("select count(*) from events").fetchone()[0]
        return out
    finally:
        con.close()


def main() -> int:
    mode, path = sys.argv[1], Path(sys.argv[2])
    if mode == "snapshot":
        path.write_text(json.dumps(fingerprint(), indent=2))
        print(path.read_text())
        return 0
    before = json.loads(path.read_text())
    after = fingerprint(before["events"]["max_id"])
    problems = []
    if before["tables"] != after["tables"]:
        problems.append(f"table list changed: {before['tables']} -> {after['tables']}")
    for name in ("endpoints", "dashboard_users"):
        if before[name] != after[name]:
            problems.append(f"{name} changed: {before[name]} -> {after[name]}")
    if before["events"] != after["events"]:
        problems.append(f"pre-existing events changed: {before['events']} -> {after['events']}")
    print(
        json.dumps(
            {
                "endpoints": after["endpoints"]["count"],
                "dashboard_users": after["dashboard_users"]["count"],
                "events_at_snapshot": before["events"]["count_at_or_below"],
                "events_pre_existing_unchanged": before["events"] == after["events"],
                "events_total_before": before["events_total_now"],
                "events_total_now": after["events_total_now"],
                "note": "events added since the snapshot can only come from the real installed agent",
                "tables_unchanged": before["tables"] == after["tables"],
            },
            indent=2,
        )
    )
    if problems:
        print("REAL DATABASE CHANGED:\n" + "\n".join(problems), file=sys.stderr)
        return 1
    print("REAL DATABASE VERIFIED UNCHANGED (apart from live agent uploads)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
