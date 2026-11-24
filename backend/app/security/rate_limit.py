"""
Small in-process sliding-window rate limiter (no Redis needed for this
single-process deployment).

- Counters live in memory: they RESET WHEN THE BACKEND RESTARTS and are NOT
  shared between multiple worker processes. That is acceptable for the current
  single-uvicorn-process deployment; if the backend is ever scaled out, move
  these to a shared store.
- A limit is a sliding window (N events per W seconds): it expires on its own,
  so nothing is ever locked permanently.
- Memory is bounded: stale keys are pruned and the table has a hard cap.
- The clock is injectable so tests can move time without sleeping.
"""

from __future__ import annotations

import threading
import time
from typing import Callable

_MAX_KEYS = 20_000
_registry: list["SlidingWindowLimiter"] = []


class SlidingWindowLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        _registry.append(self)

    def set_clock(self, clock: Callable[[], float]) -> None:
        self._clock = clock

    def _recent(self, key: str, window: float) -> list[float]:
        now = self._clock()
        recent = [t for t in self._hits.get(key, ()) if now - t < window]
        if recent:
            self._hits[key] = recent
        else:
            self._hits.pop(key, None)
        return recent

    def count(self, key: str, window: float) -> int:
        with self._lock:
            return len(self._recent(key, window))

    def retry_after(self, key: str, window: float) -> int:
        """Seconds until the oldest hit in the window expires."""
        with self._lock:
            recent = self._recent(key, window)
            return max(1, int(window - (self._clock() - recent[0]) + 0.999)) if recent else 0

    def is_limited(self, key: str, limit: int, window: float) -> bool:
        return self.count(key, window) >= limit

    def hit(self, key: str, window: float = 3600) -> None:
        with self._lock:
            if len(self._hits) >= _MAX_KEYS:
                self._prune(window)
            self._hits.setdefault(key, []).append(self._clock())

    def _prune(self, window: float) -> None:
        now = self._clock()
        for k in [k for k, v in self._hits.items() if not v or now - v[-1] >= window]:
            del self._hits[k]
        if len(self._hits) >= _MAX_KEYS:  # still full: drop the oldest half
            for k in sorted(self._hits, key=lambda k: self._hits[k][-1])[: _MAX_KEYS // 2]:
                del self._hits[k]

    def clear(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def clear_matching(self, predicate: Callable[[str], bool]) -> int:
        with self._lock:
            keys = [k for k in self._hits if predicate(k)]
            for k in keys:
                del self._hits[k]
            return len(keys)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


def reset_all() -> None:
    """Clears every limiter (tests; also what a backend restart does)."""
    for limiter in _registry:
        limiter.reset()


# One limiter per concern, so counters never bleed into each other.
login_failures_pair = SlidingWindowLimiter()  # key: "<username>|<ip>"
login_failures_ip = SlidingWindowLimiter()  # key: "<ip>"
login_failures_user = SlidingWindowLimiter()  # key: "<username>" (all IPs)
registrations = SlidingWindowLimiter()  # key: "<ip>"
request_creations = SlidingWindowLimiter()  # key: "<username>"
known_good_logins = SlidingWindowLimiter()  # key: "<username>|<ip>" successful sign-ins
enrollment_redeem_failures = SlidingWindowLimiter()  # key: "<ip>"
enrollment_mints = SlidingWindowLimiter()  # key: "<username>"
