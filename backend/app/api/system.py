"""
GET /health, GET /ready.

/health: unchanged in meaning since Phase 1 — the process is alive and
config loaded. Never checks a dependency; a dependency outage should not
make the process itself look "unhealthy" to an orchestrator that might
restart it for the wrong reason.

/ready: checks both database engines used by the API (identity/auth and
event storage) with a trivial query. Deliberately does NOT check ML
readiness: that is a real-data-sufficiency question with its own
well-defined answer at GET /api/ml/collection-status, not a process
liveness/readiness concept.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.config import settings
from app.db.database import engine as identity_engine
from app.repositories.pipeline_bridge import storage

router = APIRouter(tags=["system"])
logger = logging.getLogger(__name__)


@router.get("/health")
def health_check():
    """Simple liveness/foundation check — confirms the backend is running
    and reading configuration correctly."""
    return {
        "status": "ok",
        "app_name": settings.app_name,
        "environment": settings.environment,
    }


@router.get("/ready")
def readiness_check():
    try:
        for engine in (identity_engine, storage.engine):
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        return {"status": "ready", "database": "ok"}
    except Exception:
        logger.exception("Readiness check failed: database unavailable")
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "database": "unavailable"},
        )
