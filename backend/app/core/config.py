"""
Centralized application configuration.

All configuration is read from environment variables (with sensible local
defaults). SQLite remains the local default; production requires
`DATABASE_URL` to identify a PostgreSQL database shared by backend and event
storage. The rest of the application should only ever import `settings` from
here, never read `os.environ` directly.

Development and production share one settings object. Production settings
are validated before the app starts; cloud deployment remains unverified.
"""

import ipaddress
import re
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url


class Settings(BaseSettings):
    # General
    app_name: str = "User Behavior Anomaly Detection System"
    environment: str = "local"  # local | production

    # Backend/API
    api_host: str = "127.0.0.1"
    api_port: int = 8000

    # Structured logging level for the whole app (see logging_config.py).
    # Never set to DEBUG in production — see that module's docstring for
    # exactly what is/isn't safe to log.
    log_level: str = "INFO"

    # Storage backend switch — stays "local" until the Azure phase.
    storage_backend: str = "local"

    # Local SQLite database file, stored under data/ (gitignored). This
    # remains SQLite for local development in every phase up to and
    # including this one. Production may set the same DATABASE_URL for both
    # backend metadata and event storage, for example PostgreSQL with psycopg.
    database_url: str = "sqlite:///./data/app.db"
    database_pool_size: int = 5
    database_max_overflow: int = 5
    database_pool_timeout_seconds: int = 30
    database_pool_recycle_seconds: int = 1800
    database_connect_timeout_seconds: int = 10
    # Model artifacts are separate from event state. Local storage is the
    # development default; Azure uses the backend's configured identity.
    model_storage_provider: Literal["local", "azure_blob"] = "local"
    anomaly_model_dir: Path = Path(__file__).resolve().parents[3] / "models" / "anomaly-detection"
    azure_storage_account_url: str | None = None
    azure_storage_container: str = "ubads-models"
    installer_storage_provider: Literal["local", "azure_blob"] = "local"
    azure_installer_container: str = "ubads-installers"
    azure_installer_blob_name: str = "releases/UBADS-Agent-Setup.exe"
    applicationinsights_connection_string: str | None = None

    # Origins the frontend is allowed to call this API from. Comma-separated.
    # Local defaults cover Vite's usual dev ports on both "localhost" and
    # "127.0.0.1" (browsers treat those as distinct origins).
    # Production validation requires exact HTTPS frontend origins.
    cors_allowed_origins: str = (
        "http://localhost:5173,http://127.0.0.1:5173,"
        "http://localhost:5174,http://127.0.0.1:5174"
    )

    # --- Windows-agent authentication (Phase 9, narrowed in Phase 11) ---
    # Shared ENROLLMENT key: only accepted by POST /api/endpoints/register
    # to enroll a NEW endpoint, which then receives its own per-agent
    # credential (see backend/app/security/agent_auth.py). Heartbeat and
    # ingestion require that per-agent credential and do NOT accept this
    # key. Left unset (None) by default: enrollment is then closed (503).
    agent_api_key: str | None = None
    # Shared-key enrollment (POST /api/endpoints/register with X-Agent-Api-Key) is the legacy way
    # to add an endpoint. None (default) = enabled outside production, DISABLED in production;
    # set explicitly to true/false to override. It never affects endpoints that already hold a
    # credential (their metadata refresh, heartbeat and ingestion are separate, credentialed paths).
    legacy_enrollment_enabled: bool | None = None

    # Reserved for a future per-registered-endpoint "stale vs active"
    # status feature (see app/models/endpoint.py) — defined now as
    # configuration foundation, not yet consumed by any route. The
    # existing GET /api/endpoints/status is unchanged and still derives
    # its answer from real collected events, not from this setting.
    agent_stale_after_seconds: int = 300
    # Connection status derived from an endpoint's last_seen (agents send a
    # heartbeat every collection cycle, 60s by default):
    #   online  <= agent_online_within_seconds
    #   stale   <= agent_stale_after_seconds
    #   offline  beyond that
    agent_online_within_seconds: int = 120

    # --- Dashboard (operator) login, separate from agent auth ---
    dashboard_session_hours: int = 8
    dashboard_login_max_failures: int = 5
    dashboard_login_lockout_seconds: int = 900

    # Login throttling (sliding windows, in memory - they reset on restart):
    #   per (username, IP): dashboard_login_max_failures within the window
    #   per IP (any username): dashboard_login_max_failures_per_ip
    #   per username across ALL IPs: dashboard_login_max_failures_per_user, which
    #   does not apply to an IP that has recently signed in successfully, so a
    #   distributed attacker cannot lock the real admin out of their usual IP.
    dashboard_login_max_failures_per_ip: int = 20
    dashboard_login_max_failures_per_user: int = 30
    dashboard_known_ip_days: int = 30

    # Comma-separated IPs/CIDRs of reverse proxies whose X-Forwarded-For may
    # be trusted. Empty (default) = ignore the header, use the direct peer.
    trusted_proxies: str = ""

    # --- Phase 17: user-requested enrollment ---
    request_create_max_per_hour: int = 10  # per user
    approval_valid_days: int = 7  # how long an approval stays usable before EXPIRED
    allow_self_approval: bool = False  # an admin may not decide their own request
    registration_enabled: bool = True  # allow self-registration of normal (non-admin) accounts
    registration_max_per_hour: int = 20  # per client IP (in-memory)
    max_open_requests_per_user: int = 5  # PENDING + APPROVED requests at once
    consent_version: str = "2026-10-v1"
    # Local-development installer path. Production requires the private Azure
    # Blob installer source configured above.
    installer_path: str = ""

    # --- Phase 17 stage 4: one-time enrollment codes ---
    # Public address of THIS backend, embedded in installer enrollment codes so the
    # agent knows where to enroll. Taken ONLY from configuration, never from request
    # headers (host-header poisoning). Required as an HTTPS origin in production.
    # When empty locally it falls back to http://127.0.0.1:<API_PORT>.
    public_base_url: str = ""
    enrollment_code_ttl_minutes: int = 30  # lifetime of a minted, unredeemed code
    enrollment_mint_max_per_hour: int = 10  # per user
    enrollment_redeem_max_failures_per_ip: int = 10  # per dashboard_login_lockout_seconds window

    @property
    def legacy_enrollment_allowed(self) -> bool:
        if self.legacy_enrollment_enabled is not None:
            return self.legacy_enrollment_enabled
        return not self.is_production

    @property
    def resolved_public_base_url(self) -> str:
        """The server address to embed in enrollment codes, or "" if unusable."""
        url = self.public_base_url.strip().rstrip("/")
        if not url:
            return "" if self.is_production else f"http://127.0.0.1:{self.api_port}"
        if self.is_production and not url.lower().startswith("https://"):
            return ""  # never hand out an http:// enrollment address in production
        return url

    @property
    def resolved_installer_path(self) -> Path:
        if self.installer_path:
            return Path(self.installer_path)
        return Path(__file__).resolve().parents[3] / "agent" / "dist" / "UBADS-Agent-Setup.exe"

    @property
    def trusted_proxy_list(self) -> list[str]:
        return [p.strip() for p in self.trusted_proxies.split(",") if p.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @model_validator(mode="after")
    def validate_database_and_model_storage(self) -> "Settings":
        if self.is_production:
            parsed_database_url = make_url(self.database_url)
            driver = parsed_database_url.drivername.split("+", maxsplit=1)[0]
            if driver not in {"postgres", "postgresql"}:
                raise ValueError("DATABASE_URL must explicitly use PostgreSQL when ENVIRONMENT=production.")
            if not parsed_database_url.host or not parsed_database_url.database:
                raise ValueError(
                    "DATABASE_URL must include a PostgreSQL host and database name when "
                    "ENVIRONMENT=production."
                )
            sslmode = str(parsed_database_url.query.get("sslmode", "")).lower()
            if sslmode not in {"require", "verify-ca", "verify-full"}:
                raise ValueError(
                    "DATABASE_URL must require PostgreSQL TLS with sslmode=require, "
                    "verify-ca, or verify-full when ENVIRONMENT=production."
                )
            if self.model_storage_provider != "azure_blob":
                raise ValueError(
                    "MODEL_STORAGE_PROVIDER must be azure_blob when ENVIRONMENT=production."
                )
            if self.installer_storage_provider != "azure_blob":
                raise ValueError(
                    "INSTALLER_STORAGE_PROVIDER must be azure_blob when ENVIRONMENT=production."
                )
            public_url = urlparse(self.public_base_url.strip())
            try:
                public_url.port
            except ValueError as exc:
                raise ValueError(
                    "PUBLIC_BASE_URL must have a valid HTTPS port when ENVIRONMENT=production."
                ) from exc
            if (
                public_url.scheme != "https"
                or not public_url.hostname
                or public_url.username
                or public_url.password
                or public_url.query
                or public_url.fragment
                or public_url.path not in ("", "/")
            ):
                raise ValueError(
                    "PUBLIC_BASE_URL must be an HTTPS API origin without credentials or a path "
                    "when ENVIRONMENT=production."
                )
            self._validate_production_cors()
            self._validate_trusted_proxies()
        self._validate_database_pool_settings()
        if self.model_storage_provider == "azure_blob":
            self._validate_azure_storage_configuration("MODEL_STORAGE_PROVIDER")
        if self.installer_storage_provider == "azure_blob":
            self._validate_azure_storage_configuration("INSTALLER_STORAGE_PROVIDER")
            if not (
                3 <= len(self.azure_installer_container) <= 63
                and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", self.azure_installer_container)
            ):
                raise ValueError(
                    "AZURE_INSTALLER_CONTAINER must be a valid Azure container name when "
                    "INSTALLER_STORAGE_PROVIDER=azure_blob."
                )
            blob_parts = self.azure_installer_blob_name.split("/")
            if (
                not self.azure_installer_blob_name
                or "\\" in self.azure_installer_blob_name
                or any(part in ("", ".", "..") for part in blob_parts)
            ):
                raise ValueError(
                    "AZURE_INSTALLER_BLOB_NAME must be a non-empty relative blob name when "
                    "INSTALLER_STORAGE_PROVIDER=azure_blob."
                )
        return self

    def _validate_database_pool_settings(self) -> None:
        if self.database_pool_size < 1:
            raise ValueError("DATABASE_POOL_SIZE must be at least 1.")
        if self.database_max_overflow < 0:
            raise ValueError("DATABASE_MAX_OVERFLOW must not be negative.")
        if self.database_pool_timeout_seconds <= 0:
            raise ValueError("DATABASE_POOL_TIMEOUT_SECONDS must be positive.")
        if self.database_pool_recycle_seconds <= 0:
            raise ValueError("DATABASE_POOL_RECYCLE_SECONDS must be positive.")
        if self.database_connect_timeout_seconds <= 0:
            raise ValueError("DATABASE_CONNECT_TIMEOUT_SECONDS must be positive.")

    def _validate_azure_storage_configuration(self, provider_setting: str) -> None:
        parsed_storage_url = urlparse(self.azure_storage_account_url or "")
        if (
            parsed_storage_url.scheme != "https"
            or not parsed_storage_url.hostname
            or parsed_storage_url.username
            or parsed_storage_url.password
            or parsed_storage_url.query
            or parsed_storage_url.fragment
            or parsed_storage_url.path not in ("", "/")
        ):
            raise ValueError(
                "AZURE_STORAGE_ACCOUNT_URL must be an HTTPS account URL without embedded credentials when "
                f"{provider_setting}=azure_blob."
            )
        container_name = (
            self.azure_storage_container
            if provider_setting == "MODEL_STORAGE_PROVIDER"
            else self.azure_installer_container
        )
        if not (
            3 <= len(container_name) <= 63
            and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", container_name)
        ):
            raise ValueError(f"{provider_setting} requires a valid Azure container name.")

    def _validate_production_cors(self) -> None:
        origins = [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]
        if not origins or any("*" in origin for origin in origins):
            raise ValueError(
                "CORS_ALLOWED_ORIGINS must contain explicit HTTPS frontend origins when "
                "ENVIRONMENT=production."
            )
        for origin in origins:
            parsed = urlparse(origin)
            try:
                port = parsed.port
            except ValueError as exc:
                raise ValueError(
                    "CORS_ALLOWED_ORIGINS must contain valid HTTPS origins when ENVIRONMENT=production."
                ) from exc
            hostname = parsed.hostname
            if hostname and ":" in hostname:
                normalized_hostname = f"[{hostname.lower()}]"
            elif hostname:
                normalized_hostname = hostname.encode("idna").decode("ascii").lower()
            else:
                normalized_hostname = ""
            if port is not None and port != 443:
                normalized_hostname = f"{normalized_hostname}:{port}"
            if (
                parsed.scheme != "https"
                or not normalized_hostname
                or parsed.username
                or parsed.password
                or parsed.path
                or parsed.query
                or parsed.fragment
                or origin != f"https://{normalized_hostname}"
            ):
                raise ValueError(
                    "CORS_ALLOWED_ORIGINS must contain exact HTTPS frontend origins when "
                    "ENVIRONMENT=production."
                )

    def _validate_trusted_proxies(self) -> None:
        for proxy in self.trusted_proxy_list:
            if proxy == "*":
                raise ValueError("TRUSTED_PROXIES must not contain a wildcard.")
            try:
                ipaddress.ip_network(proxy, strict=False)
            except ValueError as exc:
                raise ValueError(
                    "TRUSTED_PROXIES must contain only explicit IP addresses or CIDR networks "
                    "when ENVIRONMENT=production."
                ) from exc

    @property
    def cors_allowed_origins_list(self) -> list[str]:
        origins = [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]
        if self.is_production and (not origins or "*" in origins):
            raise ValueError(
                "cors_allowed_origins must be set to explicit frontend origin(s) when "
                "environment=production — refusing to start with a wildcard or empty CORS "
                "policy in production."
            )
        return origins

    model_config = SettingsConfigDict(
        env_file=str(Path(__file__).resolve().parents[3] / "config" / ".env"),
        env_file_encoding="utf-8",
        hide_input_in_errors=True,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
