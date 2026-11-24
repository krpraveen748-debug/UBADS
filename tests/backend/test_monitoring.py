import microsoft.opentelemetry as microsoft_otel

from app.core.config import Settings
from app.core.monitoring import configure_application_insights


def test_application_insights_is_not_initialized_without_connection_string(monkeypatch):
    def unexpected_call(**_kwargs):
        raise AssertionError("telemetry initialization should be opt-in")

    monkeypatch.setattr(microsoft_otel, "use_microsoft_opentelemetry", unexpected_call)

    configure_application_insights(Settings(_env_file=None))


def test_application_insights_disables_sensitive_auto_instrumentation(monkeypatch):
    calls = []
    monkeypatch.setattr(
        microsoft_otel,
        "use_microsoft_opentelemetry",
        lambda **kwargs: calls.append(kwargs),
    )
    settings = Settings(
        _env_file=None,
        applicationinsights_connection_string=(
            "InstrumentationKey=00000000-0000-0000-0000-000000000000;"
            "IngestionEndpoint=https://example.invalid"
        ),
    )

    configure_application_insights(settings)

    assert calls == [
        {
            "enable_azure_monitor": True,
            "azure_monitor_connection_string": settings.applicationinsights_connection_string,
            "instrumentation_options": {
                "django": {"enabled": False},
                "fastapi": {"enabled": False},
                "flask": {"enabled": False},
                "httpx": {"enabled": False},
                "httpx2": {"enabled": False},
                "psycopg2": {"enabled": False},
                "requests": {"enabled": False},
                "urllib": {"enabled": False},
                "urllib3": {"enabled": False},
                "azure_sdk": {"enabled": False},
            },
        }
    ]
