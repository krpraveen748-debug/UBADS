"""
The ONE place this agent makes HTTP requests to the backend — every other
module calls through here rather than scattering `requests` calls
throughout the codebase.

Uses the existing backend API contracts exactly as implemented
(backend/README.md): GET /health, GET /ready, POST /api/endpoints/register,
POST /api/endpoints/heartbeat, POST /api/ingest/events. Never invents a
different ingestion mechanism and never bypasses agent authentication.

Phase 11 — per-agent credentials: two distinct auth modes, matching
backend/app/security/agent_auth.py:
  - enroll_endpoint(): presents the shared ENROLLMENT key
    (X-Agent-Api-Key, settings.agent_api_key) to register a NEW endpoint
    and receive that endpoint's own credential. Used only when this
    machine has no stored credential yet (see credential_store.py).
  - register()/heartbeat()/ingest_events(): present this endpoint's OWN
    credential (X-Endpoint-Id + X-Agent-Credential). Never send the
    enrollment key on these calls.

Retry policy: bounded exponential backoff (a few attempts, capped delay),
applied only to network-level failures (connection errors, timeouts) and
5xx responses — never to 401 (bad credentials) or 503-from-auth (agent
auth not configured), since retrying those would never succeed and would
just be a tight, pointless loop. Never retries forever.

Never logs the API key, endpoint credential, or their values — only
whether a request succeeded, and the HTTP status code on failure.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import requests

from config import settings
from connection import InvalidBackendUrl, describe_request_error, validate_backend_url

logger = logging.getLogger(__name__)

RETRYABLE_STATUS_CODES = {500, 502, 503, 504}
MAX_ATTEMPTS = 3
BACKOFF_BASE_SECONDS = 1.0


@dataclass
class BackendResult:
    ok: bool
    status_code: int | None = None
    data: dict | None = None
    error: str | None = None
    # Stage 4D: machine-readable failure classification (None on success)
    #   error_kind: "config" | "tls" | "timeout" | "network" | "http" | "server"
    #   error_code: the backend's own code for structured errors (e.g. "expired")
    error_kind: str | None = None
    error_code: str | None = None


class BackendClient:
    def __init__(self, base_url: str | None = None, *, allow_insecure_http: bool | None = None) -> None:
        raw_url = base_url if base_url is not None else settings.backend_url
        self.base_url = raw_url.rstrip("/")
        self.timeout = settings.request_timeout
        self.allow_insecure_http = settings.allow_insecure_http if allow_insecure_http is None else allow_insecure_http
        # Transport policy (https unless loopback / explicit opt-in). Checked
        # before ANY request so a credential is never sent over plain http
        # to a remote host by accident.
        try:
            validate_backend_url(self.base_url, allow_insecure_http=self.allow_insecure_http)
            self.url_error: str | None = None
        except InvalidBackendUrl as exc:
            self.url_error = str(exc)

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict | None = None,
        headers: dict | None = None,
        max_attempts: int | None = None,
    ) -> BackendResult:
        if self.url_error:
            return BackendResult(ok=False, error=self.url_error, error_kind="config")
        url = f"{self.base_url}{path}"
        attempts = max_attempts or MAX_ATTEMPTS
        last_error = None
        last_kind = None
        request_headers = {"Content-Type": "application/json"}
        if headers:
            request_headers.update(headers)

        for attempt in range(1, attempts + 1):
            try:
                response = requests.request(
                    method,
                    url,
                    json=json_body,
                    headers=request_headers,
                    timeout=self.timeout,
                )
            except requests.exceptions.SSLError as exc:
                # A bad certificate will not fix itself within a few retries.
                return BackendResult(ok=False, error=describe_request_error(exc, self.base_url), error_kind="tls")
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
                last_error = describe_request_error(exc, self.base_url)
                last_kind = "timeout" if isinstance(exc, requests.exceptions.Timeout) else "network"
                logger.warning("Attempt %d/%d: %s %s -> %s", attempt, attempts, method, path, last_error)
            else:
                if response.status_code in RETRYABLE_STATUS_CODES and attempt < attempts:
                    last_error = f"Backend returned {response.status_code}"
                    last_kind = "server"
                    logger.warning(
                        "Attempt %d/%d: %s %s -> %d (retrying)",
                        attempt,
                        attempts,
                        method,
                        path,
                        response.status_code,
                    )
                else:
                    if response.status_code >= 400:
                        error_code = None
                        try:
                            body = response.json()
                            detail = body.get("detail") if isinstance(body, dict) else response.text
                        except ValueError:
                            detail = response.text
                        if isinstance(detail, dict):  # structured error: {"code": ..., "message": ...}
                            error_code = detail.get("code")
                            detail = detail.get("message")
                        return BackendResult(
                            ok=False,
                            status_code=response.status_code,
                            error=detail,
                            error_kind="server" if response.status_code >= 500 else "http",
                            error_code=error_code,
                        )
                    try:
                        data = response.json()
                    except ValueError:
                        data = None
                    return BackendResult(ok=True, status_code=response.status_code, data=data)

            if attempt < attempts:
                time.sleep(BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)))

        return BackendResult(ok=False, error=last_error or "Request failed after retries", error_kind=last_kind or "network")

    def check_health(self) -> BackendResult:
        return self._request("GET", "/health")

    def check_ready(self) -> BackendResult:
        return self._request("GET", "/ready")

    def enroll_endpoint(
        self,
        *,
        endpoint_id: str | None,
        display_name: str,
        operating_system: str,
        agent_version: str,
        enrollment_key: str | None = None,
    ) -> BackendResult:
        """First-time enrollment: presents the shared ENROLLMENT key only.
        On success, the response includes this endpoint's own
        `agent_credential` (the only time it is ever returned) — the
        caller (agent.py) is responsible for persisting it via
        credential_store.save_credential()."""
        headers = {}
        key = enrollment_key or settings.agent_api_key
        if key:
            headers["X-Agent-Api-Key"] = key
        return self._request(
            "POST",
            "/api/endpoints/register",
            json_body={
                "endpoint_id": endpoint_id,
                "display_name": display_name,
                "operating_system": operating_system,
                "agent_version": agent_version,
            },
            headers=headers,
        )

    def _credential_headers(self, *, endpoint_id: str, agent_credential: str) -> dict:
        return {"X-Endpoint-Id": endpoint_id, "X-Agent-Credential": agent_credential}

    def register(
        self,
        *,
        endpoint_id: str,
        agent_credential: str,
        display_name: str,
        operating_system: str,
        agent_version: str,
    ) -> BackendResult:
        """Metadata refresh for an ALREADY-enrolled endpoint, authenticated
        with its own credential (never the shared enrollment key)."""
        return self._request(
            "POST",
            "/api/endpoints/register",
            json_body={
                "endpoint_id": endpoint_id,
                "display_name": display_name,
                "operating_system": operating_system,
                "agent_version": agent_version,
            },
            headers=self._credential_headers(endpoint_id=endpoint_id, agent_credential=agent_credential),
        )

    def heartbeat(self, *, endpoint_id: str, agent_credential: str) -> BackendResult:
        return self._request(
            "POST",
            "/api/endpoints/heartbeat",
            json_body={"endpoint_id": endpoint_id},
            headers=self._credential_headers(endpoint_id=endpoint_id, agent_credential=agent_credential),
        )

    def ingest_events(
        self, *, endpoint_id: str, agent_credential: str, log_name: str, events: list[dict]
    ) -> BackendResult:
        return self._request(
            "POST",
            "/api/ingest/events",
            json_body={"log_name": log_name, "endpoint_id": endpoint_id, "events": events},
            headers=self._credential_headers(endpoint_id=endpoint_id, agent_credential=agent_credential),
        )

    def redeem_enrollment(
        self,
        *,
        code: str,
        display_name: str,
        operating_system: str,
        agent_version: str,
        endpoint_id: str | None,
    ) -> BackendResult:
        """Stage 4D: trades a one-time enrollment code for this endpoint's own
        credential. Sends NO shared enrollment key and NO other auth - the code is the
        credential. A single attempt on purpose: if a request timed out AFTER the server
        committed, retrying would only report "already used" and hide what happened.
        The code is only placed in the request body; it is never logged."""
        return self._request(
            "POST",
            "/api/agent/enrollment/redeem",
            json_body={
                "code": code,
                "display_name": display_name,
                "operating_system": operating_system,
                "agent_version": agent_version,
                "endpoint_id": endpoint_id,
            },
            max_attempts=1,
        )
