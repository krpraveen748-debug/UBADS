"""
Service layer for /api/users — reuses
user_classification_diagnostics.generate_user_classification_report()
(Phase 6A.1) exactly as-is. The account-classification rules themselves
(classify_account, ACCOUNT_TYPE_EXPLANATIONS) live only in
log-collector/event_parser.py and are never re-derived here.
"""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.repositories.pipeline_bridge import storage, user_classification_diagnostics


def list_human_users(session: Session) -> list[dict]:
    try:
        events = [storage.event_record_to_dict(r) for r in storage.get_all_events(session)]
        report = user_classification_diagnostics.generate_user_classification_report(events)
    except Exception as exc:  # pragma: no cover - only on genuine storage/import failure
        raise HTTPException(status_code=503, detail=f"User classification unavailable: {exc}") from exc

    return [account for account in report["accounts"] if account["is_human_candidate"]]
