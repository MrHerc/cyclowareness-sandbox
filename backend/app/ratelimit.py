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
import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from fastapi import Request
from fastapi.responses import JSONResponse

from .auth import _secure_equals
from .config import get_settings
from .remote import client_ip

logger = logging.getLogger("sandbox.ratelimit")


@dataclass(frozen=True)
class Rule:
    """`limit` requests per `window` seconds, per credential.

    `address_limit` is the ceiling for the SAME rule charged to the caller's
    address instead. It is separate because the two buckets are doing different
    jobs, and giving them one number breaks whichever job it does not suit.

    The credential bucket is the product's limit: this is how much one API key
    or one session may do. The address bucket exists only to stop a caller
    minting a fresh credential bucket per request — so for most rules it is a
    coarse backstop, deliberately several times looser.

    That looseness is not laziness. Behind a reverse proxy with
    `TRUST_PROXY_HEADERS` off (the default, and the safe one), EVERY analyst in
    the organisation shares one address. The Queue page polls `/api/jobs` every
    three seconds, so at the credential limit of 60/60s a third analyst opening
    that page would have started getting 429s — a throttle nobody could explain
    and nothing was doing wrong.

    Authentication is the exception and keeps them equal: stopping a password
    list from one address is the entire point, and an office sharing an address
    also shares the ten-attempts-per-five-minutes it always had.
    """

    limit: int
    window: int
    name: str
    address_limit: int | None = None

    def limit_for(self, identity: str) -> int:
        if identity.startswith("ip:") and self.address_limit is not None:
            return self.address_limit
        return self.limit


#: Submission is the expensive one: it runs every analyzer and writes to
#: quarantine. Authentication is the guessable one. Everything else is a read
#: and gets a ceiling that a human clicking around will never notice but a script
#: will.
RULES: tuple[tuple[str, Rule], ...] = (
    ("/api/analyze", Rule(20, 60, "submission", address_limit=100)),
    # Equal on purpose — see Rule.
    ("/api/auth/login", Rule(10, 300, "authentication", address_limit=10)),
    ("/api/jobs", Rule(60, 60, "job-actions", address_limit=600)),
)
DEFAULT_RULE = Rule(240, 60, "read", address_limit=2400)

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
    # `_secure_equals`, not `secrets.compare_digest`. The latter raises
    # TypeError on a `str` holding a code point above U+007F, and this runs in
    # MIDDLEWARE, before any handler — so `X-Worker-Token: é` on any
    # /api/dynamic/* path was an unauthenticated 500 from an unauthenticated
    # caller. The same comparison is used at all three token sites.
    return bool(configured) and _secure_equals(presented, configured)


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


#: Sweep as soon as the dict passes this, not only every 300 seconds. The scan
#: runs under a lock in an async middleware, so its cost is a pause for every
#: caller — and a time-only trigger makes that pause a function of how much
#: traffic arrives rather than of anything this module decides.
_SWEEP_AT = 20_000

#: Hard ceiling. Roughly 250 bytes a bucket, so this is a few MB — small beside
#: the 2 GB the service is pinned to, and small enough that the scan is quick.
_MAX_BUCKETS = 50_000


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

            # LOOK UP, DO NOT CREATE.
            #
            # This used to `setdefault`, so every identity got a dict entry
            # BEFORE the fullness test could refuse the request — and an
            # attacker rotating `X-API-Key` and `Authorization` allocated two
            # new buckets per request while being answered 429 by the limiter
            # working exactly as designed. Measured on the real image: 260,000
            # requests, all but 240 refused, took RSS from 99 MiB to 230 MiB at
            # ~5,000 req/s from a single host.
            #
            # Reading first bounds it. The address bucket is the one identity a
            # caller cannot rotate, so once THAT is full every later request is
            # refused without allocating anything: the growth an attacker can
            # force is one window's worth, not one per request.
            #: Each bucket carries its own ceiling: the address bucket is a
            #: backstop against credential rotation, not the product's limit.
            found: list[tuple[str, _Bucket | None, int]] = []
            for identity in identities:
                bucket = self._buckets.get((identity, rule.name))
                if bucket is not None:
                    bucket.hits = [t for t in bucket.hits if t > cutoff]
                found.append((identity, bucket, rule.limit_for(identity)))

            full = [b for _i, b, ceiling in found if b is not None and len(b.hits) >= ceiling]
            if full:
                #: The soonest any of the exhausted buckets frees a slot.
                retry = min(int(b.hits[0] - cutoff) + 1 for b in full)
                return False, 0, max(1, retry)

            remaining = []
            for identity, bucket, ceiling in found:
                if bucket is None:
                    bucket = self._buckets.setdefault((identity, rule.name), _Bucket())
                bucket.hits.append(now)
                remaining.append(ceiling - len(bucket.hits))
            # The tightest of them, because that is the one that will stop them.
            return True, min(remaining), 0

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

        Two triggers, not one. The 300-second timer is the ordinary case. The
        size trigger is what stops the interval BEING the exposure: this runs
        under a lock inside an async middleware, so the scan blocks the whole
        single-process appliance, and a five-minute interval means the dict —
        and therefore the pause — is bounded by five minutes of traffic rather
        than by anything the limiter controls. Sweeping when it grows past
        `_SWEEP_AT` keeps both the memory and the pause proportionate.

        `_MAX_BUCKETS` is the floor under the whole thing. If a sweep cannot get
        under it — every bucket young enough to keep — the oldest are dropped
        anyway. Forgetting the least recently seen caller lets them start a
        fresh window, which is the mild failure; the alternative is an appliance
        that runs out of memory, which is the total one.
        """
        oversized = len(self._buckets) > _SWEEP_AT
        if not oversized and now - self._last_sweep < 300:
            return
        self._last_sweep = now
        stale = [k for k, b in self._buckets.items() if not b.hits or now - b.hits[-1] > 3600]
        for k in stale:
            self._buckets.pop(k, None)

        excess = len(self._buckets) - _MAX_BUCKETS
        if excess > 0:
            oldest = sorted(
                self._buckets.items(), key=lambda kv: kv[1].hits[-1] if kv[1].hits else 0.0
            )
            for k, _b in oldest[:excess]:
                self._buckets.pop(k, None)
            logger.warning(
                "rate limiter over capacity: dropped %d least-recently-seen buckets "
                "(cap %d). A caller whose bucket was dropped gets a fresh window.",
                excess,
                _MAX_BUCKETS,
            )


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
