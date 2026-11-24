"""
Tests for app/core/config.py's environment-aware CORS validation.
Constructs Settings() directly with explicit overrides — never touches the
real config/.env or the module-level cached `settings` singleton.
"""

import pytest

from app.core.config import Settings


def _production_settings(**overrides):
    values = {
        "environment": "production",
        "database_url": "postgresql+psycopg://localhost/ubads_test?sslmode=require",
        "public_base_url": "https://api.example.invalid",
        "model_storage_provider": "azure_blob",
        "azure_storage_account_url": "https://storage.example.invalid",
        "cors_allowed_origins": "https://dashboard.example.invalid",
        "installer_storage_provider": "azure_blob",
        "azure_installer_container": "ubads-installers",
        "azure_installer_blob_name": "releases/UBADS-Agent-Setup.exe",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_local_environment_is_not_production():
    s = Settings(_env_file=None, environment="local", cors_allowed_origins="http://localhost:5173")
    assert s.is_production is False
    assert s.cors_allowed_origins_list == ["http://localhost:5173"]


def test_production_environment_is_production():
    s = _production_settings(cors_allowed_origins="https://ubads.example.com")
    assert s.is_production is True


def test_production_rejects_wildcard_cors():
    with pytest.raises(ValueError):
        _production_settings(cors_allowed_origins="*")


def test_production_rejects_empty_cors():
    with pytest.raises(ValueError):
        _production_settings(cors_allowed_origins="")


def test_production_allows_explicit_origin():
    s = _production_settings(cors_allowed_origins="https://ubads.example.com")
    assert s.cors_allowed_origins_list == ["https://ubads.example.com"]


def test_local_environment_allows_wildcard_without_raising():
    # Local/dev convenience is not restricted the way production is —
    # only environment=production enforces the safe-CORS rule.
    s = Settings(_env_file=None, environment="local", cors_allowed_origins="*")
    assert s.cors_allowed_origins_list == ["*"]


def test_production_requires_postgresql_database_url():
    with pytest.raises(ValueError, match="DATABASE_URL must explicitly use PostgreSQL"):
        Settings(
            _env_file=None,
            environment="production",
            database_url="sqlite:///./data/app.db",
        )


def test_production_accepts_postgresql_database_url():
    settings = _production_settings()
    assert settings.database_url == "postgresql+psycopg://localhost/ubads_test?sslmode=require"


def test_production_requires_postgresql_tls():
    with pytest.raises(ValueError, match="must require PostgreSQL TLS"):
        _production_settings(database_url="postgresql+psycopg://localhost/ubads_test")


@pytest.mark.parametrize("sslmode", ["require", "verify-ca", "verify-full"])
def test_production_accepts_supported_postgresql_tls_modes(sslmode):
    settings = _production_settings(
        database_url=f"postgresql+psycopg://localhost/ubads_test?sslmode={sslmode}"
    )
    assert settings.database_url.endswith(f"sslmode={sslmode}")


@pytest.mark.parametrize(
    "overrides",
    [
        {"database_pool_size": 0},
        {"database_max_overflow": -1},
        {"database_pool_timeout_seconds": 0},
        {"database_pool_recycle_seconds": 0},
        {"database_connect_timeout_seconds": 0},
    ],
)
def test_database_pool_settings_must_be_positive(overrides):
    with pytest.raises(ValueError):
        Settings(_env_file=None, **overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        {"model_storage_provider": "local"},
        {"database_url": "postgresql+psycopg://localhost?sslmode=require"},
        {"public_base_url": "http://api.example.invalid"},
        {"public_base_url": "https://api.example.invalid/path"},
        {"public_base_url": "https://api.example.invalid:99999"},
        {"cors_allowed_origins": "http://dashboard.example.invalid"},
        {"cors_allowed_origins": "https://*.example.invalid"},
        {"cors_allowed_origins": "https://dashboard.example.invalid/"},
        {"cors_allowed_origins": "https://dashboard.example.invalid:443"},
        {"trusted_proxies": "*"},
        {"trusted_proxies": "proxy.example.invalid"},
    ],
)
def test_production_rejects_unsafe_deployment_settings(overrides):
    with pytest.raises(ValueError):
        _production_settings(**overrides)


def test_production_accepts_https_origins_and_explicit_proxy_ranges():
    settings = _production_settings(
        cors_allowed_origins="https://dashboard.example.invalid,https://admin.example.invalid",
        trusted_proxies="10.20.0.0/16,192.0.2.10",
    )
    assert settings.cors_allowed_origins_list == [
        "https://dashboard.example.invalid",
        "https://admin.example.invalid",
    ]


def test_azure_model_storage_requires_https_account_url_without_credentials():
    with pytest.raises(ValueError, match="HTTPS account URL") as error:
        Settings(
            _env_file=None,
            model_storage_provider="azure_blob",
            azure_storage_account_url="https://storage.example.invalid?sig=test-token",
        )
    assert "test-token" not in str(error.value)


def test_azure_model_storage_accepts_identity_based_configuration():
    settings = Settings(
        _env_file=None,
        model_storage_provider="azure_blob",
        azure_storage_account_url="https://storage.example.invalid",
        azure_storage_container="ubads-models",
    )
    assert settings.model_storage_provider == "azure_blob"


def test_azure_installer_storage_accepts_private_blob_configuration():
    settings = Settings(
        _env_file=None,
        installer_storage_provider="azure_blob",
        azure_storage_account_url="https://storage.example.invalid",
        azure_installer_container="ubads-installers",
        azure_installer_blob_name="releases/UBADS-Agent-Setup.exe",
    )
    assert settings.installer_storage_provider == "azure_blob"


@pytest.mark.parametrize(
    "overrides",
    [
        {"installer_storage_provider": "local"},
        {"azure_installer_container": "UBADS-Installers"},
        {"azure_installer_container": "x"},
        {"azure_installer_blob_name": ""},
        {"azure_installer_blob_name": "../UBADS-Agent-Setup.exe"},
    ],
)
def test_production_requires_a_valid_private_azure_installer(overrides):
    with pytest.raises(ValueError):
        _production_settings(**overrides)


def test_agent_api_key_defaults_to_none(monkeypatch):
    # Tests the CODE default, independent of a developer's local config/.env
    # (which may legitimately set AGENT_API_KEY) or an env var already
    # loaded into os.environ by another module's load_dotenv().
    monkeypatch.delenv("AGENT_API_KEY", raising=False)
    s = Settings(_env_file=None)
    assert s.agent_api_key is None
