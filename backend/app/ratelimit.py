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

import hashlib
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from fastapi import Request
from fastapi.responses import JSONResponse

from .config import get_settings
from .remote import client_ip


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

#: Paths that are never metered, matched EXACTLY. As a `startswith` test this
#: also exempted `/api/healthXXXX` and `/metricsXXXX` — any invented path with
#: the right first characters, from any unauthenticated caller, unmetered.
EXEMPT_PATHS = frozenset({"/api/health", "/metrics"})

#: The worker polls continuously by design, so metering it would meter the
#: product's own pipeline. It is exempt only when it PROVES it is the worker:
#: the same prefix without a valid token is just an unauthenticated caller, and
#: exempting those made `/api/dynamic/anything` a free request generator.
_WORKER_PREFIX = "/api/dynamic/"


def _is_exempt(request: Request, path: str) -> bool:
    if path in EXEMPT_PATHS:
        return True
    if not path.startswith(_WORKER_PREFIX):
        return False
    configured = get_settings().dynamic_worker_token
    presented = request.headers.get("x-worker-token", "")
    return bool(configured) and secrets.compare_digest(presented, configured)


def _rule_for(path: str) -> Rule:
    for prefix, rule in RULES:
        if path.startswith(prefix):
            return rule
    return DEFAULT_RULE


def _identities(request: Request) -> list[str]:
    """Every bucket this request is charged to. ALL of them must have room.

    It used to return ONE identity, preferring a credential over an address —
    and the credential came from a header the caller writes and nothing had
    validated. On `POST /api/auth/login`, which is unauthenticated by
    definition, a different random `X-API-Key` per request bought a fresh bucket
    per request: the ten-per-five-minutes authentication rule this module's own
    docstring says exists to stop a password list did nothing whatsoever, to any
    caller who added one header.

    Charging the address AS WELL closes it, and closes it without weakening the
    thing the credential bucket was right about — two tenants sharing one
    deployment must not be able to exhaust each other's allowance. A caller with
    a credential now has two budgets and is stopped by whichever runs out first,
    so rotating the credential no longer buys anything: the address bucket is
    the one they cannot choose.

    The address is only as good as `TRUST_PROXY_HEADERS` makes it — see
    `remote.client_ip`. Behind an untrusted proxy every caller shares one
    address bucket, which over-counts. That is the correct direction to be wrong
    in: a shared bucket is a limit that is too strict, and the alternative is a
    limit the caller sets themselves.

    Credentials are HASHED, never truncated. A prefix was tried — the right
    instinct, the wrong mechanism: `key:{api_key[:8]}` puts every credential
    sharing an eight-character prefix in ONE bucket, and keys are issued with
    prefixes exactly like `ck_live_`.
    """
    out = ["ip:" + (client_ip(request) or "unknown")]
    api_key = request.headers.get("x-api-key")
    if api_key:
        out.append("key:" + hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16])
    auth = request.headers.get("authorization")
    if auth:
        # Session tokens end in their HMAC, so a suffix does not collide the way
        # a key prefix does — but hash it too, for the same reason: this string
        # is stored and logged, and it is part of a bearer credential.
        out.append("auth:" + hashlib.sha256(auth.encode("utf-8")).hexdigest()[:16])
    return out


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

    def check(self, identities: str | list[str], rule: Rule) -> tuple[bool, int, int]:
        """Returns (allowed, remaining, retry_after_seconds).

        Every identity is checked BEFORE any is charged. Checking and charging
        one at a time would spend the address budget on a request the credential
        budget then refuses, so a caller who tripped one limit would burn the
        other one down too while being told no.
        """
        if isinstance(identities, str):
            identities = [identities]
        now = self._clock()
        cutoff = now - rule.window
        with self._lock:
            self._sweep(now)
            buckets = []
            for identity in identities:
                bucket = self._buckets.setdefault((identity, rule.name), _Bucket())
                bucket.hits = [t for t in bucket.hits if t > cutoff]
                buckets.append(bucket)

            full = [b for b in buckets if len(b.hits) >= rule.limit]
            if full:
                #: The soonest any of the exhausted buckets frees a slot.
                retry = min(int(b.hits[0] - cutoff) + 1 for b in full)
                return False, 0, max(1, retry)

            for bucket in buckets:
                bucket.hits.append(now)
            # The tightest of them, because that is the one that will stop them.
            return True, min(rule.limit - len(b.hits) for b in buckets), 0

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
    if request.method == "OPTIONS" or _is_exempt(request, path):
        return await call_next(request)

    rule = _rule_for(path)
    allowed, remaining, retry_after = limiter.check(_identities(request), rule)
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
