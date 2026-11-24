"""Phase 17 stage 2: login throttling (user+IP, per-IP, cross-IP), client-IP
trust, recovery, and the registration / request-creation limits."""

import time

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.security import rate_limit
from app.security.rate_limit import SlidingWindowLimiter
from tests.backend.conftest import TEST_DASHBOARD_PASSWORD, TEST_DASHBOARD_USER
from tests.backend.test_endpoint_requests import _login_client, _register, _request_body

LIMITERS = [
    rate_limit.login_failures_pair, rate_limit.login_failures_ip, rate_limit.login_failures_user,
    rate_limit.registrations, rate_limit.request_creations, rate_limit.known_good_logins,
]


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture()
def clock():
    c = FakeClock()
    for lim in LIMITERS:
        lim.set_clock(c)
    yield c
    for lim in LIMITERS:
        lim.set_clock(time.monotonic)


@pytest.fixture()
def trusted_proxy(monkeypatch):
    """TestClient's direct peer is 'testclient'; trust it as the reverse proxy."""
    monkeypatch.setattr(settings, "trusted_proxies", "testclient")


def _login(c, username=TEST_DASHBOARD_USER, password=TEST_DASHBOARD_PASSWORD, ip=None):
    headers = {"X-Forwarded-For": ip} if ip else {}
    return c.post("/api/auth/login", json={"username": username, "password": password}, headers=headers)


def _fail(c, n, username=TEST_DASHBOARD_USER, ip=None):
    return [_login(c, username, "wrong-password-xx", ip).status_code for _ in range(n)]


# --- limiter unit behaviour -------------------------------------------------


def test_limiter_window_boundaries(clock):
    lim = SlidingWindowLimiter(clock)
    for _ in range(3):
        lim.hit("k", 10)
    assert lim.is_limited("k", 3, 10) and not lim.is_limited("k", 4, 10)
    clock.advance(9.9)
    assert lim.is_limited("k", 3, 10)  # still inside the window
    assert 1 <= lim.retry_after("k", 10) <= 1
    clock.advance(0.2)
    assert not lim.is_limited("k", 3, 10)  # expired by itself - never permanent
    assert lim.count("k", 10) == 0


def test_limiter_memory_is_bounded(clock, monkeypatch):
    monkeypatch.setattr(rate_limit, "_MAX_KEYS", 50)
    lim = SlidingWindowLimiter(clock)
    for i in range(500):
        lim.hit(f"k{i}", 10)
        clock.advance(0.001)
    assert len(lim._hits) <= 50


# --- login: user+IP, per-IP, per-user --------------------------------------


def test_lockout_is_per_username_and_ip_so_an_attacker_cannot_lock_the_admin_out(anon_client, endpoint_db_session, clock, trusted_proxy):
    from app.security import dashboard_auth

    dashboard_auth.create_user(endpoint_db_session, TEST_DASHBOARD_USER, TEST_DASHBOARD_PASSWORD)
    n = settings.dashboard_login_max_failures
    assert _fail(anon_client, n, ip="198.51.100.9") == [401] * n
    assert _login(anon_client, ip="198.51.100.9").status_code == 429  # the attacker's own address is throttled
    ok = _login(anon_client, ip="203.0.113.7")  # the real admin, elsewhere, is not
    assert ok.status_code == 200


def test_429_has_retry_after_and_expires(anon_client, endpoint_db_session, clock, trusted_proxy):
    from app.security import dashboard_auth

    dashboard_auth.create_user(endpoint_db_session, TEST_DASHBOARD_USER, TEST_DASHBOARD_PASSWORD)
    _fail(anon_client, settings.dashboard_login_max_failures, ip="198.51.100.9")
    blocked = _login(anon_client, ip="198.51.100.9")
    assert blocked.status_code == 429 and int(blocked.headers["Retry-After"]) > 0
    clock.advance(settings.dashboard_login_lockout_seconds - 1)
    assert _login(anon_client, ip="198.51.100.9").status_code == 429
    clock.advance(2)
    assert _login(anon_client, ip="198.51.100.9").status_code == 200  # lockout expired on its own


def test_per_ip_limit_stops_username_spraying(anon_client, endpoint_db_session, clock, trusted_proxy, monkeypatch):
    monkeypatch.setattr(settings, "dashboard_login_max_failures_per_ip", 6)
    codes = [_login(anon_client, f"victim{i}", "wrong-password-xx", ip="198.51.100.9").status_code for i in range(8)]
    assert codes == [401] * 6 + [429] * 2  # changing usernames does not reset the per-IP budget
    assert _login(anon_client, "someone", "wrong-password-xx", ip="203.0.113.1").status_code == 401  # other IPs unaffected


def test_distributed_attack_hits_global_user_cap_but_not_the_known_good_ip(anon_client, endpoint_db_session, clock, trusted_proxy, monkeypatch):
    from app.security import dashboard_auth

    dashboard_auth.create_user(endpoint_db_session, TEST_DASHBOARD_USER, TEST_DASHBOARD_PASSWORD)
    monkeypatch.setattr(settings, "dashboard_login_max_failures_per_user", 6)
    assert _login(anon_client, ip="203.0.113.7").status_code == 200  # admin signs in from their usual IP
    for i in range(6):  # a botnet, one failure per address
        _login(anon_client, password="wrong-password-xx", ip=f"192.0.2.{i + 1}")
    assert _login(anon_client, ip="192.0.2.99").status_code == 429  # unknown address: cross-IP cap applies
    assert _login(anon_client, ip="203.0.113.7").status_code == 200  # the admin's usual IP still works


def test_nonexistent_and_existing_usernames_are_throttled_identically(anon_client, endpoint_db_session, clock, trusted_proxy):
    from app.security import dashboard_auth

    dashboard_auth.create_user(endpoint_db_session, TEST_DASHBOARD_USER, TEST_DASHBOARD_PASSWORD)
    n = settings.dashboard_login_max_failures
    real = [_login(anon_client, TEST_DASHBOARD_USER, "wrong-password-xx", "198.51.100.1").status_code for _ in range(n + 1)]
    fake = [_login(anon_client, "no-such-user", "wrong-password-xx", "198.51.100.2").status_code for _ in range(n + 1)]
    assert real == fake == [401] * n + [429]
    r1 = _login(anon_client, TEST_DASHBOARD_USER, "wrong-password-xx", "198.51.100.3")
    r2 = _login(anon_client, "no-such-user", "wrong-password-xx", "198.51.100.3")
    assert r1.status_code == r2.status_code == 401 and r1.json() == r2.json()


def test_admin_unlock_clears_throttle_and_changes_nothing_else(client, anon_client, endpoint_db_session, clock, trusted_proxy):
    n = settings.dashboard_login_max_failures
    _fail(anon_client, n, ip="198.51.100.9")
    assert _login(anon_client, ip="198.51.100.9").status_code == 429
    r = client.post("/api/admin/auth/unlock", json={"username": TEST_DASHBOARD_USER})
    assert r.status_code == 200 and r.json()["counters_cleared"] >= 1
    assert _login(anon_client, ip="198.51.100.9").status_code == 200
    assert _login(anon_client, password="not-the-password", ip="198.51.100.5").status_code == 401  # no password change


# --- client IP trust --------------------------------------------------------


def test_forwarded_header_is_ignored_unless_the_peer_is_a_trusted_proxy(anon_client, endpoint_db_session, clock):
    from app.security import dashboard_auth

    dashboard_auth.create_user(endpoint_db_session, TEST_DASHBOARD_USER, TEST_DASHBOARD_PASSWORD)
    n = settings.dashboard_login_max_failures
    # Untrusted: spoofed X-Forwarded-For values do NOT give a fresh budget.
    codes = [_login(anon_client, password="wrong-password-xx", ip=f"10.9.9.{i}").status_code for i in range(n + 1)]
    assert codes == [401] * n + [429]


def test_rightmost_untrusted_forwarded_entry_is_used(anon_client, trusted_proxy, monkeypatch):
    from starlette.requests import Request

    from app.security.client_ip import get_client_ip

    def req(xff, peer="testclient"):
        return Request({"type": "http", "client": (peer, 1), "headers": [(b"x-forwarded-for", xff.encode())] if xff else []})

    assert get_client_ip(req("203.0.113.9")) == "203.0.113.9"
    assert get_client_ip(req("6.6.6.6, 203.0.113.9")) == "203.0.113.9"  # client-supplied prefix is ignored
    assert get_client_ip(req("not-an-ip")) == "testclient"
    assert get_client_ip(req("")) == "testclient"
    assert get_client_ip(req("203.0.113.9", peer="198.51.100.77")) == "198.51.100.77"  # untrusted peer
    monkeypatch.setattr(settings, "trusted_proxies", "testclient, 10.0.0.0/8")
    assert get_client_ip(req("203.0.113.9, 10.1.2.3")) == "203.0.113.9"


# --- registration and request creation -------------------------------------


def test_registration_limit_boundary_and_isolation_per_ip(anon_client, clock, trusted_proxy, monkeypatch):
    monkeypatch.setattr(settings, "registration_max_per_hour", 3)

    def reg(name, ip):
        return anon_client.post(
            "/api/auth/register",
            json={"username": name, "password": "a-long-test-password", "email": f"{name}@x.org", "full_name": "N", "organization": "Org"},
            headers={"X-Forwarded-For": ip},
        ).status_code

    assert [reg(f"user{i}", "198.51.100.1") for i in range(3)] == [201, 201, 201]
    assert reg("user3", "198.51.100.1") == 429
    assert reg("user4", "198.51.100.2") == 201  # another IP has its own budget
    clock.advance(3601)
    assert reg("user5", "198.51.100.1") == 201


def test_failed_registrations_count_and_conflict_message_is_generic(anon_client, clock, monkeypatch):
    monkeypatch.setattr(settings, "registration_max_per_hour", 3)
    assert _register(anon_client, "dave").status_code == 201
    same_name = _register(anon_client, "dave", email="other@example.org")
    same_email = _register(anon_client, "erin", email="dave@example.org")
    assert same_name.status_code == same_email.status_code == 409
    assert same_name.json() == same_email.json()  # cannot tell which detail collided
    assert _register(anon_client, "frank").status_code == 429  # attempts count, so enumeration is bounded


def test_request_creation_limit_is_per_user(anon_client, clock, monkeypatch):
    monkeypatch.setattr(settings, "request_create_max_per_hour", 2)
    monkeypatch.setattr(settings, "max_open_requests_per_user", 50)
    _register(anon_client, "alice")
    _register(anon_client, "bob")
    alice, bob = _login_client("alice"), _login_client("bob")
    assert [alice.post("/api/endpoint-requests", json=_request_body()).status_code for _ in range(3)] == [201, 201, 429]
    assert bob.post("/api/endpoint-requests", json=_request_body()).status_code == 201  # separate counter
    clock.advance(3601)
    assert alice.post("/api/endpoint-requests", json=_request_body()).status_code == 201


def test_registration_and_login_counters_are_independent(anon_client, endpoint_db_session, clock, trusted_proxy, monkeypatch):
    monkeypatch.setattr(settings, "registration_max_per_hour", 1)
    assert _register(anon_client, "gina").status_code == 201
    assert _register(anon_client, "hank").status_code == 429
    assert _login(anon_client, "gina", "a-long-test-password").status_code == 200  # unaffected
