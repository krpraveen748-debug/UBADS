"""
Consistent, safe error responses for every route.

`HTTPException`s raised deliberately by services (404 not found, 401/503
auth/dependency failures — see backend/app/services/*.py) already carry an
intentional, safe `detail` message and pass through FastAPI's default
handling unchanged.

This module only adds a handler for the case that matters for safety:
anything UNEXPECTED (a genuine bug, an unhandled exception). Without this,
FastAPI's default behavior in some configurations can leak a Python
traceback to the client. Here, the client always gets a generic 500 with
no internal detail, while the full exception is logged server-side for
debugging — never the reverse.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


def _route_template(request: Request) -> str:
    route = request.scope.get("route")
    return getattr(route, "path", "unmatched")


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception on %s %s", request.method, _route_template(request))
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error."},
        )
