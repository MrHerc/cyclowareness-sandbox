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

When it is on, the value taken is the **last** entry of `X-Forwarded-For`, not
the first. Conventional proxies append the peer they saw
(`proxy_add_x_forwarded_for` in nginx), so a client that sends its own forged
`X-Forwarded-For: 1.2.3.4` produces `1.2.3.4, <real client>` and the last entry
is still the address the proxy actually observed. Reading the first entry — the
common mistake — reads exactly the part the attacker controls.
"""
from __future__ import annotations

from fastapi import Request

from .config import get_settings

#: Longest address string worth keeping. An IPv6 address with a zone is under
#: 60; anything beyond this is not an address, it is someone filling a column.
_MAX = 64


def client_ip(request: Request) -> str | None:
    """The caller's address, as well as this deployment can know it."""
    if get_settings().trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            #: The nearest trusted proxy appended what it saw. Everything before
            #: that is upstream hearsay, including anything the client invented.
            hop = forwarded.rsplit(",", 1)[-1].strip()
            if hop:
                return hop[:_MAX]
        real = request.headers.get("x-real-ip")
        if real and real.strip():
            return real.strip()[:_MAX]
    client = request.client
    return client.host[:_MAX] if client else None
