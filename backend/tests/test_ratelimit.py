"""Rate limiting: it exists, it lets real use through, and it cannot be walked around.

Before this there was none. `POST /api/analyze` runs every analyzer and writes to
quarantine, so anyone with an API key could drive the box over as fast as their
connection allowed, and `POST /api/auth/login` could be walked through a password
list at line speed.

A limiter is only worth having if it fails closed on abuse and stays invisible to
an analyst clicking around, so both halves are asserted here.
"""
from __future__ import annotations

import time

import pytest

from app.ratelimit import DEFAULT_RULE, RULES, RateLimiter, Rule, _identities, _rule_for


def test_a_caller_within_the_limit_is_never_blocked() -> None:
    limiter = RateLimiter()
    rule = Rule(limit=5, window=60, name="test")
    for n in range(5):
        allowed, remaining, _retry, _ceiling = limiter.check("ip:1.2.3.4", rule)
        assert allowed, f"blocked at request {n + 1} of 5"
        assert remaining == 4 - n


def test_the_caller_after_the_limit_is_blocked_with_a_retry_hint() -> None:
    limiter = RateLimiter()
    rule = Rule(limit=3, window=60, name="test")
    for _ in range(3):
        limiter.check("ip:1.2.3.4", rule)
    allowed, remaining, retry_after, _ceiling = limiter.check("ip:1.2.3.4", rule)
    assert not allowed
    assert remaining == 0
    assert 0 < retry_after <= 61, retry_after


def test_callers_are_budgeted_separately() -> None:
    """One noisy client must not lock out everyone else."""
    limiter = RateLimiter()
    rule = Rule(limit=2, window=60, name="test")
    for _ in range(2):
        limiter.check("ip:1.1.1.1", rule)
    assert not limiter.check("ip:1.1.1.1", rule)[0]
    assert limiter.check("ip:2.2.2.2", rule)[0], "a second caller was punished for the first"


def test_rules_are_budgeted_separately() -> None:
    """Exhausting uploads must not lock the analyst out of reading results."""
    limiter = RateLimiter()
    upload = Rule(limit=1, window=60, name="submission")
    read = Rule(limit=1, window=60, name="read")
    limiter.check("ip:1.2.3.4", upload)
    assert not limiter.check("ip:1.2.3.4", upload)[0]
    assert limiter.check("ip:1.2.3.4", read)[0]


class _Clock:
    """A clock the test moves, so nothing here waits on the wall.

    The first version of these tests slept. That is flaky by construction on a
    shared CI runner - it passed on a developer machine every time and turned
    the pipeline red on GitHub, where the failure said nothing about the code.
    """

    def __init__(self) -> None:
        self.t = 1_000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def test_the_window_slides_rather_than_resetting() -> None:
    """A fixed window lets a caller send 2x the limit across its boundary.

    20 requests at 0:59 and 20 more at 1:00 is 40 in two seconds while never
    breaching "20 per minute". The sliding window does not have that hole.
    """
    clock = _Clock()
    limiter = RateLimiter(clock=clock)
    rule = Rule(limit=2, window=60, name="test")
    assert limiter.check("ip:9.9.9.9", rule)[0]
    assert limiter.check("ip:9.9.9.9", rule)[0]
    assert not limiter.check("ip:9.9.9.9", rule)[0]

    clock.advance(59)
    assert not limiter.check("ip:9.9.9.9", rule)[0], "released a second too early"
    clock.advance(2)
    assert limiter.check("ip:9.9.9.9", rule)[0], "the window never released"


def test_idle_callers_are_forgotten() -> None:
    """Otherwise every address that ever called is remembered forever — an
    unbounded dict fed by strangers on a public endpoint."""
    clock = _Clock()
    limiter = RateLimiter(clock=clock)
    rule = Rule(limit=5, window=60, name="test")
    limiter.check("ip:5.5.5.5", rule)
    assert ("ip:5.5.5.5", "test") in limiter._buckets

    clock.advance(7200)  # past both the sweep interval and the idle threshold
    limiter.check("ip:6.6.6.6", rule)
    assert ("ip:5.5.5.5", "test") not in limiter._buckets, "idle caller was kept"
    assert ("ip:6.6.6.6", "test") in limiter._buckets, "the live caller was swept"


# --- the routing decisions ---------------------------------------------------


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/api/analyze", "submission"),
        ("/api/analyze/url", "submission"),
        ("/api/auth/login", "authentication"),
        ("/api/jobs/abc/reanalyze", "job-actions"),
        ("/api/result/abc", DEFAULT_RULE.name),
    ],
)
def test_expensive_paths_get_the_tight_rule(path: str, expected: str) -> None:
    assert _rule_for(path).name == expected


def test_submission_is_stricter_than_reading() -> None:
    submission = next(r for p, r in RULES if p == "/api/analyze")
    assert submission.limit < DEFAULT_RULE.limit


def test_an_api_key_identifies_a_caller_better_than_an_address() -> None:
    """Two clients behind one NAT must not share a budget when they hold keys.

    The key bucket is still there and still distinguishes them — it is no longer
    the ONLY bucket, because a caller who picks their own identity picks their
    own budget. See test_rate_limit_identity.py.
    """

    class _Req:
        def __init__(self, headers, host="10.0.0.1"):
            self.headers = headers
            self.client = type("c", (), {"host": host})()

    a = _identities(_Req({"x-api-key": "ck_aaaaaaaaaaaaaaaa"}))
    b = _identities(_Req({"x-api-key": "ck_bbbbbbbbbbbbbbbb"}))
    assert a != b
    assert [i for i in a if i.startswith("key:")] != [i for i in b if i.startswith("key:")]
    assert _identities(_Req({})) == ["ip:10.0.0.1"]
    # The address is charged whether or not a credential is present, so it can
    # never be escaped by supplying one.
    assert "ip:10.0.0.1" in a


def test_the_identity_never_carries_a_whole_credential() -> None:
    """It lands in logs and in the limiter's state; a full key belongs in neither."""

    class _Req:
        headers = {"x-api-key": "ck_supersecretvalue_do_not_log_me"}
        client = type("c", (), {"host": "10.0.0.1"})()

    assert "supersecretvalue" not in " ".join(_identities(_Req()))


# --- end to end through the app ----------------------------------------------


def test_the_analyst_ui_is_not_throttled_in_normal_use(client, auth) -> None:
    """Forty reads in a row is an ordinary session, not abuse."""
    for n in range(40):
        r = client.get("/api/jobs", headers=auth)
        assert r.status_code == 200, f"throttled a normal session at request {n + 1}"


def test_the_worker_seam_is_exempt(client) -> None:
    """The worker polls continuously by design; throttling it throttles the product."""
    for _ in range(50):
        r = client.get("/api/dynamic/queue", headers={"X-Worker-Token": "wrong"})
        assert r.status_code == 401, "the dynamic seam must answer on its own terms"


def test_health_and_metrics_stay_available_under_load(client) -> None:
    """A monitoring probe that gets 429'd reads as an outage."""
    for _ in range(60):
        assert client.get("/api/health").status_code == 200


# --- the two headers have to describe the same bucket ------------------------
#
# `X-RateLimit-Limit` always printed `rule.limit` -- the credential ceiling --
# while `X-RateLimit-Remaining` came from whichever identity bucket was
# tightest. For an anonymous caller the only identity is the address, whose
# ceiling is a deliberately wider backstop, so the live deployment answered
#
#     x-ratelimit-limit: 240
#     x-ratelimit-remaining: 2397
#
# With an API key present the two happened to agree, so it only ever misled the
# unauthenticated caller -- the one most likely to be reading them.

def test_the_limit_and_remaining_headers_come_from_one_bucket(client) -> None:
    response = client.get("/api/health")
    limit = response.headers.get("x-ratelimit-limit")
    remaining = response.headers.get("x-ratelimit-remaining")
    if limit is None or remaining is None:
        pytest.skip("this route is not rate limited")
    assert int(remaining) <= int(limit), (
        f"remaining {remaining} exceeds limit {limit}: the two describe "
        "different buckets"
    )


def test_check_reports_the_ceiling_that_bound_it() -> None:
    limiter = RateLimiter()
    rule = Rule(name="probe", limit=3, window=60)

    allowed, remaining, _retry, ceiling = limiter.check(["ip:7.7.7.7"], rule)
    assert allowed is True
    assert remaining <= ceiling, (remaining, ceiling)
    assert ceiling == rule.limit_for("ip:7.7.7.7")


def test_a_blocked_caller_is_told_the_ceiling_it_hit() -> None:
    limiter = RateLimiter()
    rule = Rule(name="probe2", limit=2, window=60)
    identity = ["ip:8.8.8.8"]

    ceiling_seen = None
    for _ in range(50):
        allowed, _remaining, _retry, ceiling = limiter.check(identity, rule)
        ceiling_seen = ceiling
        if not allowed:
            break
    assert allowed is False, "the limiter never blocked"
    assert ceiling_seen == rule.limit_for("ip:8.8.8.8"), ceiling_seen
