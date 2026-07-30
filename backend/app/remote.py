"""Who is on the other end of this request.

Two things in this codebase asked that question and got the wrong answer.

The **chain of custody** recorded `request.client.host`, which behind a reverse
proxy is the proxy. Measured on this deployment: `172.17.0.1` on every one of
275 audit rows — a field that exists to answer "who did this" and could not.

The **rate limiter** keyed its buckets on `X-API-Key` or `Authorization`, which
the caller supplies and nothing had validated yet. On `POST /api/auth/login` —
unauthenticated by definition — a different random header value per request
meant a fresh budget per request, so the ten-per-five-minutes rule that file's
docstring says exists to stop a password list did nothing at all.

Both need the same thing and neither can have it for free: a forwarding header
is written by whoever is upstream, and upstream includes the attacker unless a
proxy you trust overwrites it. So it is **opt-in**, `TRUST_PROXY_HEADERS`,
default off, and off means the socket address — wrong behind a proxy, but wrong
in the direction that over-counts rather than the one that lets a caller pick
their own identity.

When it is on, `X-Real-IP` is believed first and `X-Forwarded-For` is read
RIGHT TO LEFT. Both halves matter, and the first was wrong here until a real
nginx proved it: a very common configuration sets only
`proxy_set_header X-Real-IP $remote_addr` and passes `X-Forwarded-For` through
verbatim, so preferring the list meant preferring the one header the client
wrote. `X-Real-IP` is a single value a proxy overwrites; `X-Forwarded-For` is a
list a proxy may only append to.

Reading the list from the right is the other half: conventional proxies append
the peer they saw, so a client forging `X-Forwarded-For: 1.2.3.4` produces
`1.2.3.4, <real client>`, and the last entry is what the proxy actually
observed. Reading the first — the common mistake — reads exactly the part the
attacker controls.

Every candidate must parse as an IP address. Without that check any string at
all became an identity, which is a fresh rate-limit bucket per request and an
arbitrary value written into the chain of custody.
"""
from __future__ import annotations

import ipaddress
import logging

from fastapi import Request

from .config import get_settings

logger = logging.getLogger("sandbox.remote")

#: Longest address string worth keeping. An IPv6 address with a zone is under
#: 60; anything beyond this is not an address, it is someone filling a column.
_MAX = 64


def _as_address(value: str | None) -> str | None:
    """`value` if it is syntactically an IP address, else None.

    A forwarding header carries whatever was written into it. Without this, any
    string at all became an identity — so a caller could mint a fresh
    rate-limit bucket per request with `X-Forwarded-For: a`, `b`, `c`, and write
    those into the hash-chained chain of custody as the address that did it.
    """
    if not value:
        return None
    candidate = value.strip().strip("[]")
    # An IPv6 zone or a `host:port` from a careless proxy.
    candidate = candidate.split("%", 1)[0]
    if candidate.count(":") == 1:
        candidate = candidate.split(":", 1)[0]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return candidate[:_MAX]


def client_ip(request: Request) -> str | None:
    """The caller's address, as well as this deployment can know it."""
    settings = get_settings()
    if settings.trust_proxy_headers:
        # NAME THE HEADER. GUESSING IS THE BUG.
        #
        # This tried `X-Real-IP` first and fell through to `X-Forwarded-For`,
        # because a very common nginx sets only
        # `proxy_set_header X-Real-IP $remote_addr` and passes `X-Forwarded-For`
        # through VERBATIM. Reproduced with a real nginx in front of the real
        # image: rotating `X-Forwarded-For: 203.0.113.$i` over thirty login
        # attempts produced ZERO 429s where the control produced twenty, and a
        # successful login wrote `198.51.100.250` into the chain of custody.
        #
        # But the mirror case is just as real and the fallback did not save it.
        # An APPEND-ONLY proxy — AWS ALB, Cloudflare, Render, Heroku, or nginx
        # with only `proxy_add_x_forwarded_for` — sets NO `X-Real-IP`, so the
        # client's own `X-Real-IP` arrives untouched, is believed first, and buys
        # the same fresh rate-limit bucket and the same forged audit address.
        # DEPLOY.md blessed both configurations.
        #
        # Neither ordering is safe for the other deployment, so there is no
        # default to pick: the operator says which header their proxy writes.
        # Unset, nothing is believed and the socket peer wins — the safe
        # direction, and loud about it.
        header = (settings.proxy_client_header or "").strip().lower()
        if not header:
            logger.warning(
                "TRUST_PROXY_HEADERS is on but PROXY_CLIENT_HEADER is unset, so no "
                "forwarding header is believed and the socket peer is used. Set it to "
                "the header your proxy WRITES: 'x-real-ip' (nginx proxy_set_header) or "
                "'x-forwarded-for' (ALB / Cloudflare / Render / nginx "
                "proxy_add_x_forwarded_for)."
            )
        elif header == "x-real-ip":
            # A single value the proxy overwrites.
            real = _as_address(request.headers.get("x-real-ip"))
            if real:
                return real
        elif header == "x-forwarded-for":
            # Right to left: the nearest trusted proxy appended what it saw, and
            # everything before that is upstream hearsay. Empty and non-address
            # entries are skipped rather than falling through to another
            # client-writable header — `X-Forwarded-For: 9.9.9.9,` did that.
            for hop in reversed((request.headers.get("x-forwarded-for") or "").split(",")):
                address = _as_address(hop)
                if address:
                    return address
        else:
            logger.warning(
                "PROXY_CLIENT_HEADER=%r is not a header this understands; no "
                "forwarding header is believed. Use 'x-real-ip' or 'x-forwarded-for'.",
                header,
            )
    client = request.client
    return client.host[:_MAX] if client else None
