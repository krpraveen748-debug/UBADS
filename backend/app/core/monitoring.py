"""Optional Azure Monitor initialization using the Microsoft OpenTelemetry distro."""

from app.core.config import Settings


def configure_application_insights(settings: Settings) -> None:
    connection_string = settings.applicationinsights_connection_string
    if not connection_string:
        return

    from microsoft.opentelemetry import use_microsoft_opentelemetry

    use_microsoft_opentelemetry(
        enable_azure_monitor=True,
        azure_monitor_connection_string=connection_string,
        instrumentation_options={
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
    )
