"""No shape of token may crash the authentication path.

Probed against the live image with 25 shapes; five returned 500:

    body is a JSON list     claims.get on a list   -> AttributeError
    body is a JSON string    same                  -> AttributeError
    exp is "soon"            int("soon")           -> ValueError
    exp is null              int(None)             -> TypeError
    exp is [1]               int([1])              -> TypeError

Every one needs a VALID SIGNATURE, so none is remotely exploitable by someone
without the signing key. They still matter: a token minted by an older build
with a different claim shape crashes the request instead of being rejected —
which is precisely what an upgrade produces — and a 500 out of the auth path
writes a stack trace and trips whatever watches the error rate, for what is
simply an invalid credential.

`_verify_token` already caught `JSONDecodeError` with exactly this intention,
so the rest were an omission rather than a decision.
"""
from __future__ import annotations

import base64
import json
import time

import pytest

from app.auth import _sign, _verify_token, issue_token
from app.config import ensure_secret_key, get_settings


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _signed(claims) -> str:
    """A token carrying `claims`, signed with the REAL key."""
    body = json.dumps(claims, separators=(",", ":")).encode("utf-8")
    return f"{_b64e(body)}.{_sign(body, ensure_secret_key(get_settings()))}"


MALFORMED = [
    ("body is a list", _signed([1, 2, 3])),
    ("body is a string", _signed("hello")),
    ("body is a number", _signed(7)),
    ("body is null", _signed(None)),
    ("exp is a word", _signed({"sub": "x", "exp": "soon"})),
    ("exp is null", _signed({"sub": "x", "exp": None})),
    ("exp is a list", _signed({"sub": "x", "exp": [1]})),
    ("exp is a dict", _signed({"sub": "x", "exp": {"t": 1}})),
    ("no exp", _signed({"sub": "x"})),
    ("expired", _signed({"sub": "x", "exp": 1})),
    ("sub missing", _signed({"exp": 10 ** 12})),
    ("sub is a number", _signed({"sub": 7, "exp": 10 ** 12})),
    ("sub is empty", _signed({"sub": "", "exp": 10 ** 12})),
]


@pytest.mark.parametrize("name,token", MALFORMED, ids=[n for n, _ in MALFORMED])
def test_verify_returns_none_instead_of_raising(name, token) -> None:
    """The unit: no exception, and no identity."""
    assert _verify_token(token, get_settings()) is None


@pytest.mark.parametrize("name,token", MALFORMED, ids=[n for n, _ in MALFORMED])
def test_the_endpoint_answers_401(client, name, token) -> None:
    """And end to end, because the crash was in the request path."""
    response = client.get("/api/jobs", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401, (name, response.status_code)


@pytest.mark.parametrize("token", [
    "", ".", "abcdef", "!!!!.sig", "a.b.c",
    _b64e(b"x" * 200_000) + ".sig",
])
def test_structurally_broken_tokens_are_401(client, token) -> None:
    response = client.get("/api/jobs", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401, token[:40]


def test_a_forged_signature_is_refused(client) -> None:
    good, _exp = issue_token("probe", settings=get_settings())
    forged = good[: good.rindex(".") + 1] + "AAAA"
    assert client.get("/api/jobs", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_the_valid_shapes_still_work() -> None:
    """Hardening must not have narrowed what a real token may carry."""
    settings = get_settings()
    now = int(time.time())

    # A float exp, which json.dumps produces from time.time().
    assert _verify_token(_signed({"sub": "a", "exp": now + 999.9}), settings) is not None
    # A very distant exp.
    assert _verify_token(_signed({"sub": "a", "exp": 10 ** 30}), settings) is not None
    # A non-string tenant falls back rather than failing — a pre-tenancy token
    # is signed and unexpired and its jobs were backfilled to the default.
    identity = _verify_token(_signed({"sub": "a", "exp": now + 60, "tnt": 5}), settings)
    assert identity is not None and identity.tenant == settings.analyst_tenant_name
    # And the real thing.
    good, _ = issue_token("analyst", settings=settings)
    assert _verify_token(good, settings) is not None
