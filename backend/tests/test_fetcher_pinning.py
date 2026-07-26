"""The two properties that make the URL fetcher safe to expose.

``test_fetcher_ssrf`` pins the *refusals* at the ``assert_safe`` gate. These
tests pin what happens once the gate has been passed, which is where an audit
found the real holes:

* the guard resolved a name, httpx resolved it a second time, and the second
  answer was 127.0.0.1 — the check was decorative, and internal bytes landed in
  quarantine;
* the body was read with ``response.content``, so a chunked 400 MB reply was
  buffered whole before the 32 MB cap was consulted.

Both are exercised against a stubbed transport, so the suite opens no sockets
and depends on no DNS.
"""
from __future__ import annotations

import socket

import httpx
import pytest

from app.engine import fetcher
from app.engine.storage import SampleTooLarge

#: Any routable-looking address. Nothing ever connects to it — the transport is
#: stubbed — it only has to survive the private/reserved-range check.
PUBLIC = "93.184.216.34"


class _Chunks(httpx.SyncByteStream):
    def __init__(self, iterator):
        self._iterator = iterator

    def __iter__(self):
        return iter(self._iterator)


def _stub_dns(monkeypatch, answers):
    """Resolve names from `answers`, falling back to the host itself for literals.

    `answers` maps a hostname to the list of addresses to hand out, one per
    lookup, so a test can model a resolver that rebinds on the second call.
    """
    lookups: list[str] = []

    def getaddrinfo(host, port, *args, **kwargs):
        lookups.append(host)
        sequence = answers.get(host)
        if sequence is None:
            address = host
        else:
            address = sequence[min(lookups.count(host), len(sequence)) - 1]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port or 0))]

    monkeypatch.setattr(fetcher.socket, "getaddrinfo", getaddrinfo)
    return lookups


def _stub_transport(monkeypatch, responder):
    """Replace the real transport; record every request that reaches it."""
    seen: list[httpx.Request] = []

    def handle_request(self, request):
        seen.append(request)
        return responder(request)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", handle_request)
    return seen


def test_connection_is_pinned_to_the_validated_address(monkeypatch):
    # A resolver that answers publicly once and then rebinds to loopback. The
    # fetch must never see the second answer: it resolves once and connects to
    # the address it validated.
    lookups = _stub_dns(monkeypatch, {"rebind.test": [PUBLIC, "127.0.0.1"]})
    seen = _stub_transport(
        monkeypatch,
        lambda request: httpx.Response(200, stream=_Chunks([b"payload"])),
    )

    result = fetcher.fetch("http://rebind.test/sample.bin")

    assert lookups == ["rebind.test"], "a second lookup is a rebinding window"
    assert seen[0].url.host == PUBLIC
    assert result.stored.size_bytes == len(b"payload")


def test_pinning_preserves_the_host_header_and_tls_sni(monkeypatch):
    # Pinning must not cost virtual hosting or certificate verification: the
    # request is addressed to the hostname even though it is aimed at the IP.
    _stub_dns(monkeypatch, {"files.test": [PUBLIC]})
    seen = _stub_transport(
        monkeypatch,
        lambda request: httpx.Response(200, stream=_Chunks([b"payload"])),
    )

    fetcher.fetch("https://files.test:8443/sample.bin")

    assert seen[0].url.host == PUBLIC
    assert seen[0].headers["Host"] == "files.test:8443"
    assert seen[0].extensions["sni_hostname"] == "files.test"


def test_redirect_into_a_private_address_is_refused(monkeypatch):
    _stub_dns(monkeypatch, {"cdn.test": [PUBLIC]})
    seen = _stub_transport(
        monkeypatch,
        lambda request: httpx.Response(
            302,
            headers={"location": "http://127.0.0.1:8080/admin"},
            stream=_Chunks([]),
        ),
    )

    with pytest.raises(fetcher.UnsafeURL):
        fetcher.fetch("http://cdn.test/sample.bin")

    # The private hop was refused before a request for it was ever built.
    assert len(seen) == 1


def test_oversized_streamed_body_aborts_before_it_is_buffered(monkeypatch):
    _stub_dns(monkeypatch, {"big.test": [PUBLIC]})
    produced = 0

    def body():
        nonlocal produced
        for _ in range(400):  # 400 MiB if anything ever asked for all of it
            produced += 1
            yield b"\0" * (1024 * 1024)

    _stub_transport(
        monkeypatch,
        # No Content-Length: the declared-size check cannot help here, so only
        # the streaming cap stands between the sender and the heap.
        lambda request: httpx.Response(200, stream=_Chunks(body())),
    )

    with pytest.raises(SampleTooLarge):
        fetcher.fetch("http://big.test/huge.bin", max_bytes=2 * 1024 * 1024)

    assert produced <= 4, f"read {produced} MiB against a 2 MiB cap"


def test_declared_content_length_over_the_cap_is_refused(monkeypatch):
    _stub_dns(monkeypatch, {"big.test": [PUBLIC]})
    _stub_transport(
        monkeypatch,
        lambda request: httpx.Response(
            200, headers={"content-length": str(64 * 1024 * 1024)}, stream=_Chunks([])
        ),
    )

    with pytest.raises(SampleTooLarge):
        fetcher.fetch("http://big.test/huge.bin", max_bytes=2 * 1024 * 1024)
