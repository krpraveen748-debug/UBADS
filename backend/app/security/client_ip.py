"""
Client IP for rate limiting.

By default the DIRECT connection address is used and X-Forwarded-For is
IGNORED - a client can put anything in that header. Only when the direct
peer is listed in TRUSTED_PROXIES (comma-separated IPs/CIDRs of YOUR reverse
proxy) is X-Forwarded-For consulted, and then only the right-most entry that
is not itself a trusted proxy is used (the address your proxy actually saw).
"""

from __future__ import annotations

import ipaddress

from fastapi import Request

from app.core.config import settings


def _is_trusted(host: str, trusted: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return host in trusted
    for entry in trusted:
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            if host == entry:
                return True
    return False


def get_client_ip(request: Request) -> str:
    peer = request.client.host if request.client else "unknown"
    trusted = settings.trusted_proxy_list
    if not trusted or not _is_trusted(peer, trusted):
        return peer
    hops = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
    for hop in reversed(hops):
        if _is_trusted(hop, trusted):
            continue
        try:
            ipaddress.ip_address(hop)
        except ValueError:
            return peer  # garbage in the header: do not trust any of it
        return hop
    return peer
