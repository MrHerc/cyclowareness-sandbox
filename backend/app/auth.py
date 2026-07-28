"""Access control.

File analysis is a privileged operation — it accepts hostile input by design —
so every route that submits, mutates or exports is gated. Two credentials open
the gate, and nothing else does:

* a **session token**, issued by ``POST /api/auth/login`` against the one
  configured analyst account, for the web UI; and
* a **static API key** (``X-API-Key``), for programmatic access to
  ``/api/analyze`` — the REST-endpoint use case the brief rewards.

The two credentials are not equivalent in scope. A session belongs to a person
who typed a password; an API key is a static string pasted into a CI pipeline or
a SIEM connector, and is submit-only. ``require_admin`` enforces that split.

The session token is a compact, HMAC-signed, expiring blob built from the
standard library — no JWT dependency, no asymmetric-key ceremony, and no
opportunity to accept ``alg: none``. Signature verification and password
comparison are both constant-time.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, status

from .config import Settings, ensure_secret_key, get_settings


@dataclass(frozen=True)
class Identity:
    """Who is making a request, once authenticated."""

    subject: str
    method: str  # "session" | "api_key"
    #: Which tenant's data this identity may see. Every job is stamped with one
    #: at creation and every read is scoped to it, so this is the whole of the
    #: isolation boundary — if a query forgets it, the boundary is not there.
    #:
    #: Not optional and never empty: a default would be a silent hole, and the
    #: one thing worse than no isolation is isolation that appears to be on.
    tenant: str


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(txt: str) -> bytes:
    pad = "=" * (-len(txt) % 4)
    return base64.urlsafe_b64decode(txt + pad)


def _secure_equals(candidate: str, expected: str) -> bool:
    """Constant-time comparison that survives non-ASCII input.

    ``hmac.compare_digest`` raises ``TypeError`` when a ``str`` argument holds a
    code point above U+007F, so an ``X-API-Key: 0xE9`` header — or an analyst
    password containing an Azerbaijani or Turkish letter — turned a failed
    authentication into an unauthenticated 500, and made any such
    ``ANALYST_PASSWORD`` permanently unusable. Comparing the UTF-8 encodings
    keeps the comparison constant-time and accepts any Unicode credential.
    """
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


def _sign(payload: bytes, key: str) -> str:
    mac = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).digest()
    return _b64e(mac)


def issue_token(subject: str, *, settings: Settings | None = None) -> tuple[str, int]:
    """Return ``(token, expires_at_epoch)`` for an authenticated analyst.

    The tenant is a signed claim rather than something re-read from settings on
    each request: a token must keep meaning exactly what it meant when it was
    issued. Re-reading would silently move every live session the moment an
    operator edited ``ANALYST_TENANT``.
    """
    settings = settings or get_settings()
    key = ensure_secret_key(settings)
    exp = int(time.time()) + settings.token_ttl_hours * 3600
    body = json.dumps(
        {"sub": subject, "exp": exp, "tnt": settings.analyst_tenant_name},
        separators=(",", ":"),
    ).encode("utf-8")
    token = f"{_b64e(body)}.{_sign(body, key)}"
    return token, exp


def _verify_token(token: str, settings: Settings) -> Identity | None:
    try:
        body_b64, sig = token.split(".", 1)
        body = _b64d(body_b64)
    except (ValueError, Exception):  # noqa: BLE001 — malformed token is just invalid
        return None
    key = ensure_secret_key(settings)
    if not _secure_equals(sig, _sign(body, key)):
        return None
    try:
        claims = json.loads(body)
    except json.JSONDecodeError:
        return None
    if int(claims.get("exp", 0)) < int(time.time()):
        return None
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        return None
    # A token issued before tenancy existed carries no claim. It is signed and
    # unexpired, so it is valid — and it belongs to the default tenant, which is
    # where its jobs were backfilled. Rejecting it would log every analyst out on
    # deploy; inventing a different tenant would hide their own data from them.
    tenant = claims.get("tnt")
    if not isinstance(tenant, str) or not tenant:
        tenant = settings.analyst_tenant_name
    return Identity(subject=subject, method="session", tenant=tenant)


def verify_login(username: str, password: str, settings: Settings) -> bool:
    """Constant-time check against the configured analyst account."""
    user_ok = _secure_equals(username, settings.analyst_username)
    pass_ok = _secure_equals(password, settings.analyst_password)
    return user_ok and pass_ok


def _match_api_key(candidate: str, settings: Settings) -> str | None:
    """The tenant this key belongs to, or None if it is not a configured key.

    Every configured key is compared even after a match, so the time taken does
    not depend on which key matched or on how far down the list it is.
    """
    found: str | None = None
    for key, tenant in settings.api_key_tenants:
        if _secure_equals(candidate, key) and found is None:
            found = tenant
    return found


_UNAUTH = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Authentication required",
    headers={"WWW-Authenticate": "Bearer"},
)


def require_analyst(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> Identity:
    """FastAPI dependency: reject anything without a valid token or API key."""
    if authorization and authorization.lower().startswith("bearer "):
        identity = _verify_token(authorization[7:].strip(), settings)
        if identity is not None:
            return identity
    if x_api_key:
        tenant = _match_api_key(x_api_key.strip(), settings)
        if tenant is not None:
            # The subject names the tenant so the audit trail can tell two API
            # clients apart. It was "api-client" for everyone, which made every
            # programmatic action in the custody chain indistinguishable.
            return Identity(subject=f"api-client:{tenant}", method="api_key", tenant=tenant)
    raise _UNAUTH


def require_admin(identity: Identity = Depends(require_analyst)) -> Identity:
    """FastAPI dependency for the deployment-wide tuning routes.

    An API key is a submit-only credential handed to a pipeline; it must not also
    be able to re-weight scoring for every user of the deployment. Those routes
    therefore demand an interactive session, which only ``POST /api/auth/login``
    issues against the analyst account.
    """
    if identity.method != "session":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administration requires an analyst session, not an API key",
        )
    return identity
