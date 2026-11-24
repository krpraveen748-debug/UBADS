"""
Phase 6A.1 — user/account classification diagnostics.

Read-only: answers "why is/isn't this account being treated as a human
candidate?" for every account actually present in the real stored events.
Reuses event_parser.ACCOUNT_TYPE_EXPLANATIONS (the single source of truth
for what each classify_account() result means) rather than duplicating
that reasoning here.

Privacy note: this report intentionally does NOT include each account's
raw SID or any `raw_event_data` — only the username/domain (already
visible throughout this project's other output, e.g. `--show`) and
account_type. A boolean `sid_present` is reported instead of the SID
value itself, since the diagnostic's purpose (explaining classification)
doesn't need the exact identifier.

Grouping note: this groups accounts by (domain, username) — the natural
key for a human reviewing "is this account a real person" — which
differs from user_identity.resolve_user_id() (SID-preferring) used by
feature_engineering.py/collection_status.py for precise per-user
aggregation. Both are legitimate; they serve different purposes.
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

_LOG_COLLECTOR_DIR = Path(__file__).resolve().parent.parent / "log-collector"
if str(_LOG_COLLECTOR_DIR) not in sys.path:
    sys.path.insert(0, str(_LOG_COLLECTOR_DIR))

from event_parser import ACCOUNT_TYPE_EXPLANATIONS, classify_account  # noqa: E402

HUMAN_CANDIDATE_ACCOUNT_TYPE = "human_or_unknown"


def _account_key(event: dict) -> tuple[str | None, str | None]:
    return (event.get("domain"), event.get("username"))


def generate_user_classification_report(events: list[dict]) -> dict:
    accounts: dict[tuple, dict] = {}
    account_type_counts: Counter = Counter()
    categorized_count = 0
    uncategorized_count = 0

    for e in events:
        key = _account_key(e)
        username = e.get("username")
        domain = e.get("domain")
        user_sid = e.get("user_sid")
        # Re-derive account_type from the raw identity fields rather than
        # trusting the stored `account_type` column — this diagnostic then
        # also surfaces cases where classification logic changed after
        # events were already stored (exactly what happened in this phase).
        account_type = classify_account(username, user_sid)
        account_type_counts[account_type] += 1

        category = e.get("event_category")
        if category and category != "uncategorized":
            categorized_count += 1
        else:
            uncategorized_count += 1

        if key not in accounts:
            accounts[key] = {
                "username": username,
                "domain": domain,
                "account_type": account_type,
                "event_count": 0,
                "sid_present": bool(user_sid),
                "is_human_candidate": account_type == HUMAN_CANDIDATE_ACCOUNT_TYPE,
                "exclusion_reason": (
                    None
                    if account_type == HUMAN_CANDIDATE_ACCOUNT_TYPE
                    else ACCOUNT_TYPE_EXPLANATIONS.get(account_type, "Unrecognized account_type value.")
                ),
            }
        accounts[key]["event_count"] += 1

    return {
        "total_events": len(events),
        "total_distinct_accounts": len(accounts),
        "accounts": sorted(accounts.values(), key=lambda a: a["event_count"], reverse=True),
        "event_counts_by_account_type": dict(account_type_counts),
        "categorized_vs_uncategorized": {
            "categorized": categorized_count,
            "uncategorized": uncategorized_count,
        },
        "human_candidate_account_count": sum(
            1 for a in accounts.values() if a["is_human_candidate"]
        ),
    }
