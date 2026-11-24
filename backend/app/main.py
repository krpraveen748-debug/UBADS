"""
FastAPI application entrypoint.

Phase 8C: real API routes backing the frontend (events, users, ml/
collection-status, reports/data-quality, endpoints/status, anomalies).
Each router's actual logic lives in backend/app/services/ +
backend/app/repositories/pipeline_bridge.py, which reuses log-collector's
and ml-service's existing functions directly — nothing here re-implements
event storage, classification, or readiness rules.

Phase 9: production-readiness foundation — environment-aware config,
structured logging, a safe unhandled-exception handler, GET /ready, and a
protected (disabled-by-default) foundation for future Windows-agent
endpoints (register/heartbeat/ingest). See backend/README.md for the full
IMPLEMENTED vs. PLANNED breakdown.
"""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.errors import register_error_handlers
from app.core.logging_config import configure_logging
from app.core.monitoring import configure_application_insights
from app.security.dashboard_auth import require_admin

configure_logging(settings.log_level)
configure_application_insights(settings)
logger = logging.getLogger(__name__)

from app.api import admin_endpoint_requests, agent_enrollment, anomalies, notifications, auth, endpoint_requests, endpoint_identity, endpoint_status, events, ingest, ml, reports, system, users  # noqa: E402


@asynccontextmanager
async def lifespan(_app: FastAPI):
    logger.info("Starting %s (environment=%s)", settings.app_name, settings.environment)
    logger.info("CORS allowed origins: %s", settings.cors_allowed_origins_list)
    if not settings.agent_api_key:
        logger.info(
            "AGENT_API_KEY (enrollment key) is not set — new agent enrollment is closed. "
            "Already-enrolled agents can still authenticate with their own credentials."
        )
    yield
    logger.info("Shutting down %s", settings.app_name)


app = FastAPI(title=settings.app_name, lifespan=lifespan)

register_error_handlers(app)


@app.middleware("http")
async def log_request_summary(request: Request, call_next):
    started_at = time.perf_counter()
    response = await call_next(request)
    route = request.scope.get("route")
    route_template = getattr(route, "path", "unmatched")
    elapsed_ms = (time.perf_counter() - started_at) * 1000
    logger.info(
        "HTTP request method=%s route=%s status=%d duration_ms=%.2f",
        request.method,
        route_template,
        response.status_code,
        elapsed_ms,
    )
    return response


# Allows the frontend (a separate origin — the Vite dev server locally, a
# real deployed origin in production) to call this API from the browser.
# In production, cors_allowed_origins_list refuses to allow "*" or an
# empty list — see app/core/config.py.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins_list,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "X-Enrollment-Expires-At"],  # the portal reads the package file name
)

# Dashboard read APIs: every route requires an ADMIN session (Phase 17: self-registered
# normal users must never read telemetry or the endpoint list).
# Agent routes (endpoint_identity POSTs, ingest) use agent credentials
# instead and are NOT behind this dependency; /health and /ready stay open.
_dashboard = [Depends(require_admin)]

app.include_router(system.router)
app.include_router(auth.router)
app.include_router(endpoint_requests.router)
app.include_router(notifications.router)
app.include_router(admin_endpoint_requests.router)  # router-level require_admin
app.include_router(events.router, dependencies=_dashboard)
app.include_router(users.router, dependencies=_dashboard)
app.include_router(anomalies.router, dependencies=_dashboard)
app.include_router(ml.router, dependencies=_dashboard)
app.include_router(reports.router, dependencies=_dashboard)
app.include_router(endpoint_status.router, dependencies=_dashboard)
app.include_router(endpoint_identity.router)
app.include_router(ingest.router)
app.include_router(agent_enrollment.router)  # code-authenticated; not a dashboard route
