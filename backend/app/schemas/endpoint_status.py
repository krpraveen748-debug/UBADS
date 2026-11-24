from __future__ import annotations

from pydantic import BaseModel


class EndpointStatus(BaseModel):
    """GET /api/endpoints/status.

    `online`, `collectorRunning`, and `lastHeartbeat` are always `null` —
    this local prototype's collector runs as a one-shot CLI script, not a
    persistent agent reporting heartbeats, so those facts are genuinely
    not verifiable from the backend. `status` is always "unknown" for the
    same reason. Every other field is a real fact derived from stored
    events (or null if there are none) — never a guess.
    """

    endpointName: str | None = None
    online: bool | None = None
    collectorRunning: bool | None = None
    lastHeartbeat: str | None = None
    lastEvent: str | None = None
    eventsPerMinute: float | None = None
    currentUser: str | None = None
    categories: list[str] = []
    status: str = "unknown"
