"""
Backend URL policy and human-readable connection errors.

- validate_backend_url(): normalises the URL and enforces the transport
  policy — https everywhere except loopback; plain http to a non-loopback
  host only with an explicit opt-in (allow_insecure_http).
- describe_request_error(): turns a `requests` exception into a message an
  end user can act on (DNS vs refused vs timeout vs TLS), instead of a
  generic "could not connect".
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

import requests


class InvalidBackendUrl(ValueError):
    pass


def is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_backend_url(url: str, *, allow_insecure_http: bool = False, allow_loopback: bool = True) -> str:
    """Returns the normalised base URL (no path/trailing slash) or raises
    InvalidBackendUrl with a message fit to show to the user."""
    candidate = (url or "").strip()
    parsed = urlparse(candidate)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise InvalidBackendUrl("The backend URL must look like https://ubads.example.com (include http:// or https://).")
    try:
        parsed.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError:
        raise InvalidBackendUrl("The backend URL has an invalid port number.") from None
    if parsed.username or parsed.password:
        raise InvalidBackendUrl("Do not put a username or password in the backend URL.")

    loopback = is_loopback_host(parsed.hostname)
    if loopback and not allow_loopback:
        raise InvalidBackendUrl(
            "localhost / 127.0.0.1 points at THIS computer, not your UBADS server. "
            "Use the server's real address (for example https://ubads.example.com)."
        )
    if parsed.scheme == "http" and not loopback and not allow_insecure_http:
        raise InvalidBackendUrl(
            "Plain http:// would send this computer's credentials unencrypted. Use an https:// address. "
            "(For a trusted private-network trial only, re-run setup with --allow-insecure-http.)"
        )
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def describe_request_error(exc: Exception, base_url: str) -> str:
    text = str(exc).lower()
    if isinstance(exc, requests.exceptions.SSLError):
        return (
            f"Secure connection to {base_url} failed: the server's TLS certificate could not be verified "
            "(expired, self-signed, or wrong host name)."
        )
    if isinstance(exc, requests.exceptions.Timeout):
        return f"{base_url} timed out (no answer). Check the address, your network, and that the server is running."
    if isinstance(exc, requests.exceptions.ConnectionError):
        if any(s in text for s in ("getaddrinfo", "name or service not known", "nameresolution", "failed to resolve")):
            return f"The host name in {base_url} could not be found (DNS lookup failed). Check the spelling and your internet connection."
        if "refused" in text or "10061" in text:
            return f"{base_url} refused the connection. The server may be stopped, the port wrong, or a firewall is blocking it."
        return f"Could not connect to {base_url}. Check your network connection and the server address."
    return f"Request to {base_url} failed: {type(exc).__name__}"
