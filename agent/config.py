"""Agent settings with a protected, environment-independent installed mode."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

import paths
from connection import InvalidBackendUrl, validate_backend_url
from paths import get_config_dir, get_user_config_path


PRODUCTION_CONFIG_ERROR: str | None = None
PRODUCTION_CONFIG_MISSING = False
_PRODUCTION_CONFIG_FIELDS = {
    "backend_url",
    "categories",
    "log_channel",
    "collection_interval",
    "batch_size",
    "request_timeout",
    "log_level",
}


class AgentSettings(BaseSettings):
    backend_url: str = "http://127.0.0.1:8000"
    agent_api_key: str | None = None
    endpoint_id: str | None = None

    collection_interval: int = 60
    batch_size: int = 50
    request_timeout: float = 10.0
    allow_insecure_http: bool = False
    log_level: str = "INFO"
    categories: str = "authentication,file_activity,process_activity,device_activity"
    log_channel: str = "Security"

    @property
    def category_list(self) -> list[str]:
        return [category.strip() for category in self.categories.split(",") if category.strip()]

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        if paths.is_frozen_production():
            return (init_settings,)
        if paths.is_test_mode():
            return init_settings, env_settings
        return init_settings, env_settings, dotenv_settings, file_secret_settings

    model_config = SettingsConfigDict(
        env_file=(str(get_config_dir() / ".env"), str(get_user_config_path())),
        env_file_encoding="utf-8",
        extra="ignore",
    )


def _read_production_config(config_path: Path) -> dict[str, Any]:
    data = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError("unsupported config format")
    if set(data) - (_PRODUCTION_CONFIG_FIELDS | {"version"}):
        raise ValueError("unsupported config key")
    if "backend_url" not in data or not isinstance(data["backend_url"], str):
        raise ValueError("missing backend URL")
    data = {key: value for key, value in data.items() if key != "version"}
    data["backend_url"] = validate_backend_url(
        data["backend_url"], allow_insecure_http=False, allow_loopback=False
    )
    data["allow_insecure_http"] = False
    return data


def load_settings() -> AgentSettings:
    global PRODUCTION_CONFIG_ERROR, PRODUCTION_CONFIG_MISSING
    PRODUCTION_CONFIG_ERROR = None
    PRODUCTION_CONFIG_MISSING = False
    if not paths.is_frozen_production():
        return AgentSettings()

    config_path = paths.get_trusted_config_path()
    try:
        if config_path.exists():
            from protected_storage import verify_protected_storage

            verify_protected_storage()
        trusted_values = _read_production_config(config_path)
    except FileNotFoundError:
        PRODUCTION_CONFIG_MISSING = True
        PRODUCTION_CONFIG_ERROR = "The protected agent configuration is missing."
        return AgentSettings(backend_url="", _env_file=None)
    except (OSError, ValueError, InvalidBackendUrl, TypeError, RuntimeError):
        PRODUCTION_CONFIG_ERROR = "The protected agent configuration is invalid or inaccessible."
        return AgentSettings(backend_url="", _env_file=None)
    try:
        return AgentSettings(**trusted_values, _env_file=None)
    except (TypeError, ValueError):
        PRODUCTION_CONFIG_ERROR = "The protected agent configuration is invalid or inaccessible."
        return AgentSettings(backend_url="", _env_file=None)


settings = load_settings()
