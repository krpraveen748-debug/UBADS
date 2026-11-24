"""Read and write non-secret agent settings."""

from __future__ import annotations

import json
import os

import paths
from connection import validate_backend_url
from paths import get_user_config_path
from protected_storage import secure_storage_file


_PRODUCTION_KEYS = {
    "BACKEND_URL": "backend_url",
    "CATEGORIES": "categories",
    "LOG_CHANNEL": "log_channel",
    "COLLECTION_INTERVAL": "collection_interval",
    "BATCH_SIZE": "batch_size",
    "REQUEST_TIMEOUT": "request_timeout",
}


def read_user_config() -> dict[str, str]:
    path = get_user_config_path()
    if not path.exists():
        return {}
    if paths.is_frozen_production():
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") != 1:
            raise ValueError("The protected agent configuration is invalid.")
        return {
            key.upper(): str(data[value])
            for key, value in _PRODUCTION_KEYS.items()
            if value in data
        }

    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip().upper()] = value.strip()
    return values


def write_user_config(updates: dict[str, str]) -> None:
    path = get_user_config_path()
    if paths.is_frozen_production():
        from protected_storage import ensure_protected_storage

        values = read_user_config()
        values.update({key.upper(): value for key, value in updates.items()})
        unsupported = set(values) - set(_PRODUCTION_KEYS) - {"ALLOW_INSECURE_HTTP"}
        if unsupported or values.get("ALLOW_INSECURE_HTTP", "false").lower() != "false":
            raise ValueError("Unsupported or insecure production configuration.")
        payload = {"version": 1}
        for key, value in values.items():
            if key == "ALLOW_INSECURE_HTTP":
                continue
            payload[_PRODUCTION_KEYS[key]] = value
        if not payload.get("backend_url"):
            raise ValueError("A backend URL is required.")
        payload["backend_url"] = validate_backend_url(
            payload["backend_url"], allow_insecure_http=False, allow_loopback=False
        )
        ensure_protected_storage()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.touch(exist_ok=True)
        secure_storage_file(temporary)
        temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        secure_storage_file(temporary)
        os.replace(temporary, path)
        secure_storage_file(path)
        return

    values = read_user_config()
    values.update({key.upper(): value for key, value in updates.items()})
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "# Written by 'ubads-agent --setup'.\n"
    body += "".join(f"{key}={value}\n" for key, value in sorted(values.items()))
    temporary = path.with_suffix(".tmp")
    temporary.write_text(body, encoding="utf-8")
    os.replace(temporary, path)
