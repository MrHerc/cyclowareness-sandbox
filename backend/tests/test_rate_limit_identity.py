"""A caller must not be able to choose their own rate-limit budget.

`_identity()` returned ONE identity and preferred a credential over an address:

    api_key = request.headers.get("x-api-key")
    if api_key:
        return "key:" + sha256(api_key)...

That header is written by the caller and nothing had validated it. On
`POST /api/auth/login` — unauthenticated by definition — sending a different
random `X-API-Key` with each request produced a different bucket for each
request, so the ten-per-five-minutes rule the module docstring says exists to
stop "a password list at line speed" stopped nothing at all, from any caller who
added one header they fully control.

The fix charges EVERY identity a request has, and refuses when any of them is
out. The credential bucket was right about something real — two tenants on one
deployment must not exhaust each other's allowance — so it stays; the address
bucket is simply added underneath it, and the address is the one the caller
cannot pick.

The address itself is only as good as the deployment says it is. Behind an
untrusted proxy every caller shares one bucket, which over-counts; that is the
correct direction to be wrong in, and `TRUST_PROXY_HEADERS` is how an operator
who terminates TLS at a proxy they control gets the real one back.

Turning that switch on is not enough, because there is no safe ordering of the
two forwarding headers: whichever is believed first, some real deployment does
not write it, and the client's own copy survives to be believed. So the operator
also names the header their proxy WRITES, with `PROXY_CLIENT_HEADER`, and only
that one is read. Unnamed, nothing is believed and the socket peer wins.
"""
from __future__ import annotations

import pytest

from app import ratelimit
from app.config import get_settings


@pytest.fixture(autouse=True)
def _fresh():
    ratelimit.limiter.reset()
    yield
    ratelimit.limiter.reset()


LOGIN = {"username": "analyst", "password": "wrong-on-purpose"}


def _login(client, headers=None):
    return client.post("/api/auth/login", json=LOGIN, headers=headers or {})


def test_rotating_an_api_key_does_not_buy_a_fresh_budget(client) -> None:
    """The finding, exactly. Eleven attempts, a different key on each."""
    seen = []
    for n in range(14):
        response = _login(client, {"X-API-Key": f"invented-{n}"})
        seen.append(response.status_code)
    assert 429 in seen, (
        f"a password list walked {len(seen)} attempts unthrottled: {seen}"
    )


def test_rotating_a_bearer_token_does_not_either(client) -> None:
    seen = [_login(client, {"Authorization": f"Bearer forged-{n}"}).status_code for n in range(14)]
    assert 429 in seen, seen


def test_no_credential_at_all_is_still_limited(client) -> None:
    """The path that always worked, asserted so the fix cannot regress it."""
    seen = [_login(client).status_code for _ in range(14)]
    assert 429 in seen, seen


def test_a_legitimate_caller_still_gets_their_own_allowance(client) -> None:
    """The credential bucket exists so one tenant cannot exhaust another's.
    Adding the address bucket must not have taken that away — but in the suite
    both tenants share one address, so what is asserted is the narrower and
    still-necessary thing: the buckets are per-credential, and a caller who has
    not spent theirs is not refused because of someone else's key."""
    assert ratelimit.limiter.check(["ip:1.2.3.4", "key:aaa"], ratelimit.Rule(2, 60, "t"))[0]
    assert ratelimit.limiter.check(["ip:5.6.7.8", "key:bbb"], ratelimit.Rule(2, 60, "t"))[0]
    # `key:aaa` has one hit, `key:bbb` has one hit, and neither address is spent.
    assert ratelimit.limiter.check(["ip:5.6.7.8", "key:bbb"], ratelimit.Rule(2, 60, "t"))[0]
    assert not ratelimit.limiter.check(["ip:5.6.7.8", "key:bbb"], ratelimit.Rule(2, 60, "t"))[0]
    # ...and the other caller is untouched by that.
    assert ratelimit.limiter.check(["ip:1.2.3.4", "key:aaa"], ratelimit.Rule(2, 60, "t"))[0]


def test_a_refused_request_does_not_spend_the_other_bucket(client) -> None:
    """Check every bucket before charging any. Charging as you go spends the
    address budget on a request the credential budget then refuses."""
    rule = ratelimit.Rule(1, 60, "t")
    assert ratelimit.limiter.check(["ip:9.9.9.9", "key:ccc"], rule)[0]
    # `key:ccc` is now full. This attempt must be refused...
    assert not ratelimit.limiter.check(["ip:8.8.8.8", "key:ccc"], rule)[0]
    # ...without having spent 8.8.8.8, which had done nothing wrong.
    assert ratelimit.limiter.check(["ip:8.8.8.8", "key:ddd"], rule)[0]


# --- which address, and who is allowed to say -------------------------------


def _identities(client, headers):
    """The identities the middleware would charge for a request with `headers`."""
    captured: list[list[str]] = []
    original = ratelimit._identities

    def spy(request):
        captured.append(original(request))
        return captured[-1]

    ratelimit._identities = spy
    try:
        client.get("/api/jobs", headers=headers)
    finally:
        ratelimit._identities = original
    return captured[-1] if captured else []


def test_a_forwarded_header_is_ignored_by_default(client) -> None:
    """It is written by whoever is upstream, and upstream includes the caller."""
    assert not get_settings().trust_proxy_headers
    ids = _identities(client, {"X-Forwarded-For": "203.0.113.7"})
    assert not any(i == "ip:203.0.113.7" for i in ids), ids


def _trust(monkeypatch, header: str) -> None:
    """Turn the switch on and name the header the proxy writes."""
    settings = get_settings()
    monkeypatch.setattr(settings, "trust_proxy_headers", True)
    monkeypatch.setattr(settings, "proxy_client_header", header)


def test_when_trusted_the_LAST_hop_is_taken_not_the_first(client, monkeypatch) -> None:
    """Proxies APPEND the peer they saw, so a client that forges its own
    `X-Forwarded-For: 1.2.3.4` produces `1.2.3.4, <real client>`. Reading the
    first entry — the common mistake — reads exactly the part the attacker
    wrote."""
    _trust(monkeypatch, "x-forwarded-for")
    ids = _identities(client, {"X-Forwarded-For": "1.2.3.4, 198.51.100.9"})
    assert "ip:198.51.100.9" in ids, ids
    assert "ip:1.2.3.4" not in ids, ids


# --- the exemption list ------------------------------------------------------


def test_the_exemption_is_an_exact_path_not_a_prefix(client) -> None:
    """`startswith(("/api/health", "/metrics"))` also exempted
    `/api/healthXXXX` and `/metricsXXXX` — any invented path with the right
    first characters, from any unauthenticated caller, unmetered forever."""
    from app.ratelimit import _is_exempt

    class _Req:
        headers: dict = {}

    assert _is_exempt(_Req(), "/api/health")
    assert _is_exempt(_Req(), "/metrics")
    assert not _is_exempt(_Req(), "/api/healthzzzz")
    assert not _is_exempt(_Req(), "/metrics-not-really")
    assert not _is_exempt(_Req(), "/api/health/../jobs")


def test_the_worker_seam_is_exempt_only_with_the_token(client) -> None:
    """Exempting the prefix outright made `/api/dynamic/anything` a free,
    unauthenticated request generator."""
    from app.ratelimit import _is_exempt

    token = get_settings().dynamic_worker_token

    class _Req:
        def __init__(self, headers):
            self.headers = headers

    assert _is_exempt(_Req({"x-worker-token": token}), "/api/dynamic/queue")
    assert not _is_exempt(_Req({}), "/api/dynamic/queue")
    assert not _is_exempt(_Req({"x-worker-token": "wrong"}), "/api/dynamic/queue")
    assert not _is_exempt(_Req({}), "/api/dynamic/anything-invented")


# --- the address bucket is a backstop, not the product's limit ---------------


def test_analysts_behind_one_proxy_do_not_throttle_each_other(client) -> None:
    """With TRUST_PROXY_HEADERS off — the default, and the safe one — every
    analyst in the organisation shares ONE address. The Queue page polls
    /api/jobs every three seconds, so a single shared 60/60s ceiling meant the
    third analyst to open that page started getting 429s for no reason anyone
    could see. The credential bucket stays at 60; the address bucket is the
    coarse backstop it was added to be."""
    jobs = next(r for p, r in ratelimit.RULES if p == "/api/jobs")
    assert jobs.limit_for("key:abc") == jobs.limit
    assert jobs.limit_for("ip:172.17.0.1") > jobs.limit * 5, (
        "the shared-address ceiling is tight enough to throttle a second analyst"
    )

    # Six analysts polling every three seconds for a minute.
    per_analyst = 20
    rule = ratelimit.Rule(jobs.limit, jobs.window, "sim", address_limit=jobs.address_limit)
    refused = 0
    for tick in range(per_analyst):
        for analyst in range(6):
            ok, _rem, _retry = ratelimit.limiter.check(
                ["ip:172.17.0.1", f"auth:analyst{analyst}"], rule
            )
            refused += 0 if ok else 1
    assert refused == 0, f"{refused} of {per_analyst * 6} legitimate polls were refused"


def test_authentication_keeps_the_address_ceiling_tight(client) -> None:
    """The one rule where the address bucket IS the limit: stopping a password
    list from one address is the whole reason it exists."""
    login = next(r for p, r in ratelimit.RULES if p == "/api/auth/login")
    assert login.limit_for("ip:1.2.3.4") == login.limit, (
        "a loose address ceiling on login would reopen the bypass this closes"
    )


def test_a_single_credential_is_still_held_to_its_own_limit(client) -> None:
    """Loosening the address bucket must not loosen the product's limit."""
    rule = ratelimit.Rule(3, 60, "one-caller", address_limit=1000)
    ok = [ratelimit.limiter.check(["ip:9.9.9.9", "key:solo"], rule)[0] for _ in range(5)]
    assert ok == [True, True, True, False, False], ok


# --- only the header the operator named is believed ---------------------------


@pytest.mark.parametrize("header,headers,expected", [
    # nginx `proxy_set_header X-Real-IP $remote_addr` and XFF passed through
    # verbatim. Reproduced with a real nginx: believing the list meant thirty
    # rotating login attempts produced ZERO 429s where the control produced 20.
    ("x-real-ip", {"X-Real-IP": "10.0.0.1", "X-Forwarded-For": "203.0.113.9"}, "ip:10.0.0.1"),
    # `proxy_add_x_forwarded_for` — the proxy appends what it saw, so the last
    # entry is real and everything before it is the client's contribution.
    ("x-forwarded-for", {"X-Forwarded-For": "1.2.3.4, 198.51.100.9"}, "ip:198.51.100.9"),
    # An empty last element used to make the whole list falsy and fall through
    # to the equally client-written X-Real-IP.
    ("x-forwarded-for", {"X-Forwarded-For": "9.9.9.9,", "X-Real-IP": ""}, "ip:9.9.9.9"),
    # Not addresses. Any string at all was an identity, so `a`, `b`, `c` was a
    # fresh bucket each time — and an arbitrary value in the audit trail.
    ("x-forwarded-for", {"X-Forwarded-For": "not-an-address"}, None),
    ("x-real-ip", {"X-Real-IP": "'; DROP TABLE audit_events; --"}, None),
    ("x-forwarded-for", {"X-Forwarded-For": "a, b, c"}, None),
    # Shapes a careless proxy really does emit.
    ("x-real-ip", {"X-Real-IP": "[2001:db8::1]"}, "ip:2001:db8::1"),
    ("x-real-ip", {"X-Real-IP": "198.51.100.9:51234"}, "ip:198.51.100.9"),
    # THE HEADER THAT WAS NOT NAMED IS CLIENT-WRITTEN TEXT. Both rows are a real
    # deployment the old code got wrong: behind an append-only proxy (ALB,
    # Cloudflare, Render) no `X-Real-IP` is set, so the client's own arrives
    # untouched — and it was believed first.
    ("x-forwarded-for", {"X-Real-IP": "203.0.113.9"}, None),
    ("x-real-ip", {"X-Forwarded-For": "203.0.113.9"}, None),
    # Unset, and misspelt: believe nothing, charge the socket.
    ("", {"X-Real-IP": "10.0.0.1", "X-Forwarded-For": "203.0.113.9"}, None),
    ("x-client-ip", {"X-Real-IP": "10.0.0.1"}, None),
    # The operator's own value is normalised, not required to be typed exactly.
    ("  X-Real-IP  ", {"X-Real-IP": "10.0.0.1"}, "ip:10.0.0.1"),
])
def test_which_forwarded_value_is_believed(client, monkeypatch, header, headers, expected) -> None:
    _trust(monkeypatch, header)
    ids = _identities(client, headers)
    addresses = [i for i in ids if i.startswith("ip:")]
    assert len(addresses) == 1, addresses
    if expected is None:
        # Falls back to the socket, which the caller cannot choose.
        assert addresses[0] not in {"ip:" + v for v in headers.values()}
        for value in headers.values():
            assert value not in addresses[0]
    else:
        assert addresses[0] == expected, (header, headers, ids)


@pytest.mark.parametrize("header,forge", [
    # The nginx-that-sets-X-Real-IP deployment: the forged list is ignored.
    ("x-real-ip", "X-Forwarded-For"),
    # The append-only deployment: the forged single value is ignored. This is
    # the case the old ordering lost — it believed X-Real-IP first, and here
    # nothing upstream ever writes X-Real-IP.
    ("x-forwarded-for", "X-Real-IP"),
    # Nothing named at all: the socket peer, so still one bucket.
    ("", "X-Forwarded-For"),
])
def test_a_forged_header_cannot_mint_buckets_when_trust_is_on(
    client, monkeypatch, header, forge
) -> None:
    """The attack, end to end: rotate the header the proxy does NOT write and
    try to walk the login limit."""
    _trust(monkeypatch, header)
    seen = [
        _login(client, {forge: f"203.0.113.{n}"}).status_code
        for n in range(14)
    ]
    assert 429 in seen, f"a rotating {forge} walked {len(seen)} attempts: {seen}"


def test_one_tenant_cannot_exhaust_another_behind_a_shared_address(client) -> None:
    """The guarantee ratelimit.py states, tested with the REAL rules.

    On a deployment behind docker-proxy every caller arrives from one address —
    measured, `172.17.0.1` on all 1188 non-worker audit rows — so the address
    bucket really is shared by everyone. If its ceiling equalled the credential
    ceiling, the first tenant to spend theirs would lock out every other tenant
    with an untouched budget of their own. The multiplier is what stops that,
    and this walks each real rule to prove it.
    """
    for path, rule in ratelimit.RULES + (("/api/other", ratelimit.DEFAULT_RULE),):
        if rule.name == "authentication":
            continue  # equal on purpose — see Rule
        ratelimit.limiter.reset()
        shared = "ip:172.17.0.1"

        # Tenant A spends its entire credential allowance.
        for _ in range(rule.limit):
            assert ratelimit.limiter.check([shared, "key:tenantA"], rule)[0], path
        assert not ratelimit.limiter.check([shared, "key:tenantA"], rule)[0], (
            f"{path}: tenant A was not held to its own limit"
        )

        # Tenant B, untouched, must still be served.
        assert ratelimit.limiter.check([shared, "key:tenantB"], rule)[0], (
            f"{path}: tenant A exhausting its own budget locked out tenant B"
        )
