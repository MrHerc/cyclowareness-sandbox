"""Rate limiting, in process, with no new dependency.

There was none at all. `POST /api/analyze` runs the whole static engine — YARA
over the file, oletools, pefile, archive expansion — and writes the sample to
disk. Anyone holding an API key could drive that as fast as their connection
allowed until the box fell over or the quarantine filled, and `POST
/api/auth/login` could be walked through a password list at line speed.

Deliberately not `slowapi` or Redis. This ships as a single-process appliance
into environments that are often air-gapped, and a rate limiter that needs a
second service is a rate limiter operators turn off. The trade is stated
plainly below rather than hidden.

**Scope, honestly:** the counters live in this process. One instance is one
budget, which is exactly right for the appliance this is, and wrong the moment
someone runs several replicas behind a load balancer — then each replica permits
the full rate. A deployment that does that needs a shared store, and
`X-RateLimit-Scope: process` says so in every response rather than leaving an
operator to discover it.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from fastapi import Request
from fastapi.responses import JSONResponse


@dataclass(frozen=True)
class Rule:
    """`limit` requests per `window` seconds."""

    limit: int
    window: int
    name: str


#: Submission is the expensive one: it runs every analyzer and writes to
#: quarantine. Authentication is the guessable one. Everything else is a read
#: and gets a ceiling that a human clicking around will never notice but a script
#: will.
RULES: tuple[tuple[str, Rule], ...] = (
    ("/api/analyze", Rule(20, 60, "submission")),
    ("/api/auth/login", Rule(10, 300, "authentication")),
    ("/api/jobs", Rule(60, 60, "job-actions")),
)
DEFAULT_RULE = Rule(240, 60, "read")

#: The worker polls continuously by design and authenticates with a token only it
#: holds; throttling it would throttle the product's own pipeline.
EXEMPT_PREFIXES = ("/api/dynamic/", "/api/health", "/metrics")


def _rule_for(path: str) -> Rule:
    for prefix, rule in RULES:
        if path.startswith(prefix):
            return rule
    return DEFAULT_RULE


def _identity(request: Request) -> str:
    """Who to charge. An API key is a stronger identity than an address.

    Only a prefix of the key is used: this string ends up in logs and in the
    limiter's own state, and a full credential should not be in either.
    """
    api_key = request.headers.get("x-api-key")
    if api_key:
        return f"key:{api_key[:8]}"
    auth = request.headers.get("authorization")
    if auth:
        return f"auth:{auth[-12:]}"
    client = request.client
    return f"ip:{client.host if client else 'unknown'}"


@dataclass
class _Bucket:
    hits: list[float] = field(default_factory=list)


class RateLimiter:
    """Sliding window, because a fixed window lets a caller send 2x the limit.

    A fixed 60-second window resets on the minute, so 20 requests at 0:59 and 20
    more at 1:00 is 40 in two seconds while never breaching "20 per minute". The
    sliding window costs a list of timestamps per caller and does not have that
    hole.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        # The clock is injectable so tests can advance it instead of sleeping.
        # Timing tests that sleep are flaky by construction on a shared CI
        # runner - this limiter's first version had one, and it turned the
        # pipeline red on a machine where nothing was wrong.
        self._clock = clock
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        self._lock = threading.Lock()
        self._last_sweep = clock()

    def check(self, identity: str, rule: Rule) -> tuple[bool, int, int]:
        """Returns (allowed, remaining, retry_after_seconds)."""
        now = self._clock()
        key = (identity, rule.name)
        with self._lock:
            self._sweep(now)
            bucket = self._buckets.setdefault(key, _Bucket())
            cutoff = now - rule.window
            bucket.hits = [t for t in bucket.hits if t > cutoff]
            if len(bucket.hits) >= rule.limit:
                retry = int(bucket.hits[0] - cutoff) + 1
                return False, 0, max(1, retry)
            bucket.hits.append(now)
            return True, rule.limit - len(bucket.hits), 0

    def reset(self) -> None:
        """Forget every caller. For tests, which are not an attacker.

        A suite that logs in a few hundred times is legitimate traffic shaped
        like abuse, and the answer is to give each test a clean limiter rather
        than to loosen the production limits until the suite fits under them.
        Ten logins per five minutes is the right number for a real deployment.
        """
        with self._lock:
            self._buckets.clear()
            self._last_sweep = self._clock()

    def _sweep(self, now: float) -> None:
        """Drop idle buckets so a long-running instance does not leak memory.

        Without this, every distinct client address that ever called is
        remembered forever — which on a public endpoint is an unbounded dict fed
        by strangers.
        """
        if now - self._last_sweep < 300:
            return
        self._last_sweep = now
        stale = [k for k, b in self._buckets.items() if not b.hits or now - b.hits[-1] > 3600]
        for k in stale:
            self._buckets.pop(k, None)


limiter = RateLimiter()


async def rate_limit_middleware(request: Request, call_next):
    path = request.url.path
    if request.method == "OPTIONS" or path.startswith(EXEMPT_PREFIXES):
        return await call_next(request)

    rule = _rule_for(path)
    allowed, remaining, retry_after = limiter.check(_identity(request), rule)
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={
                "detail": (
                    f"Rate limit exceeded for {rule.name}: "
                    f"{rule.limit} requests per {rule.window}s. "
                    f"Retry in {retry_after}s."
                )
            },
            headers={
                "Retry-After": str(retry_after),
                "X-RateLimit-Limit": str(rule.limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Scope": "process",
            },
        )

    response = await call_next(request)
    response.headers["X-RateLimit-Limit"] = str(rule.limit)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    response.headers["X-RateLimit-Scope"] = "process"
    return response
