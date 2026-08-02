"""Being refused must not be a way to grow the thing doing the refusing.

`check` used to `setdefault` a bucket for every identity BEFORE the fullness
test could return 429 — so a caller rotating `X-API-Key` and `Authorization`
allocated two dict entries per request while the limiter answered 429 to every
one of them, working exactly as designed. Measured on the real image: 260,000
requests, all but 240 refused, took RSS from 99 MiB to 230 MiB at ~5,000 req/s
from a single host, and `_sweep`'s 300-second gate meant the peak was a function
of arrival rate rather than of anything this module decided.

Reading before creating bounds it: the address bucket is the one identity a
caller cannot rotate, so once that is full every later request is refused
without allocating anything.

And the 429 itself has to be readable. It is produced by a middleware, and a
response that never reaches the route also never reaches whatever adds the CORS
headers if the ordering is wrong — leaving a browser on a split origin with an
opaque network error in place of "retry in 34 seconds".
"""
from __future__ import annotations

import pytest

from app import ratelimit
from app.ratelimit import RateLimiter, Rule


@pytest.fixture(autouse=True)
def _fresh():
    ratelimit.limiter.reset()
    yield
    ratelimit.limiter.reset()


def test_a_refused_request_allocates_nothing() -> None:
    limiter = RateLimiter()
    rule = Rule(2, 60, "t", address_limit=2)

    for n in range(2):
        assert limiter.check(["ip:9.9.9.9", f"key:rotating-{n}"], rule)[0]
    size = len(limiter._buckets)

    # The address bucket is full. Every one of these is refused, and every one
    # of them presents a credential nobody has seen before.
    for n in range(500):
        allowed, _remaining, _retry, _ceiling = limiter.check(
            ["ip:9.9.9.9", f"key:invented-{n}", f"auth:invented-{n}"], rule
        )
        assert not allowed
    assert len(limiter._buckets) == size, (
        f"being throttled grew the limiter from {size} to {len(limiter._buckets)} buckets"
    )


def test_the_dict_is_capped_even_if_every_bucket_is_young(monkeypatch) -> None:
    """The floor under the whole thing. A sweep that finds nothing stale still
    has to get back under the ceiling, or the appliance runs out of memory."""
    monkeypatch.setattr(ratelimit, "_SWEEP_AT", 50)
    monkeypatch.setattr(ratelimit, "_MAX_BUCKETS", 100)
    limiter = RateLimiter()
    rule = Rule(1000, 60, "t", address_limit=1000)

    for n in range(400):
        limiter.check([f"ip:10.0.0.{n % 255}", f"key:k{n}"], rule)

    # The sweep runs at the top of `check`, so the call that triggers it still
    # inserts its own identities afterwards: the steady state is the cap plus
    # one request's worth, not the cap exactly. Bounded is the property.
    assert len(limiter._buckets) <= 100 + 2, len(limiter._buckets)


def test_dropping_a_bucket_gives_that_caller_a_fresh_window(monkeypatch) -> None:
    """The failure mode, stated: forgetting the least recently seen caller lets
    them start again. That is the mild half of the trade and it should be
    visible in a test rather than discovered."""
    monkeypatch.setattr(ratelimit, "_SWEEP_AT", 4)
    monkeypatch.setattr(ratelimit, "_MAX_BUCKETS", 4)
    limiter = RateLimiter()
    rule = Rule(1, 60, "t", address_limit=1)

    assert limiter.check(["ip:1.1.1.1"], rule)[0]
    assert not limiter.check(["ip:1.1.1.1"], rule)[0]
    for n in range(20):
        limiter.check([f"ip:2.2.2.{n}"], rule)
    assert limiter.check(["ip:1.1.1.1"], rule)[0]


# --- the 429 has to be readable by the thing that got it ---------------------


ORIGIN = {"Origin": "http://localhost:5173"}


def test_a_429_carries_the_cors_headers(client) -> None:
    """A browser on the Vite dev origin — the documented local setup — must be
    able to READ the rate-limit message. Without the header it sees an opaque
    network failure and the UI reports the API as unreachable, which is the
    opposite of what happened."""
    last = None
    for _ in range(14):
        last = client.post(
            "/api/auth/login",
            json={"username": "analyst", "password": "no"},
            headers=ORIGIN,
        )
        if last.status_code == 429:
            break
    assert last is not None and last.status_code == 429, "the limiter never fired"
    assert last.headers.get("access-control-allow-origin"), dict(last.headers)
    assert last.headers.get("retry-after")
    assert "detail" in last.json()


def test_an_ordinary_response_carries_them_too(client) -> None:
    """The control. If this fails the CORS configuration is wrong generally and
    the test above proves nothing about ordering."""
    response = client.get("/api/health", headers=ORIGIN)
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin"), dict(response.headers)
