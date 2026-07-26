"""Fetch a sample from a URL the submitter supplied.

This is the most dangerous function in the engine, and not because of what it
downloads. A server that fetches arbitrary user-supplied URLs is a **Server-Side
Request Forgery** primitive: on a cloud host, `http://169.254.169.254/` is the
instance metadata service and hands out credentials to anyone who asks from
inside the network. "Analyse this URL for me" is exactly the shape of request an
attacker wants a security tool to honour.

So every URL is resolved and checked **before** the connection is made, every
redirect hop is re-checked (a permitted host can 302 into a private address),
and the connection is pinned to an address that was actually validated.

Pinning is what makes the check worth anything. Validating a hostname and then
handing that same hostname to the HTTP client resolves it *twice*, and a name
that answers with a public address on the first lookup is free to answer with
127.0.0.1 on the second — classic DNS rebinding. An audit drove exactly that:
the guard saw a public address, the socket landed on loopback, and the bytes of
an internal service were quarantined as a "sample". So the request is issued
against the validated IP literal, with the original ``Host`` header and the
original hostname as TLS SNI, which keeps certificate verification bound to the
name the submitter asked for rather than to the address.

Known residuals, stated plainly rather than papered over:

* Only the first validated address is used. Every address the name resolved to
  was checked, so this is safe, but a host whose first record is unreachable
  fails instead of falling back the way the OS resolver would.
* A name that resolves differently per hop is re-resolved and re-validated per
  hop; within a single response body the connection stays on the pinned address.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from .storage import MAX_SAMPLE_BYTES, SampleTooLarge, store_stream, StoredSample

TIMEOUT_SECONDS = 30.0
MAX_REDIRECTS = 3
RETRIES = 3

ALLOWED_SCHEMES = {"http", "https"}

#: Cloud metadata endpoints. Blocked by address below as well, but named
#: explicitly because they are the single highest-value SSRF target.
_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.goog",
    "100.100.100.200",
}


class UnsafeURL(ValueError):
    pass


class FetchFailed(RuntimeError):
    pass


@dataclass
class Fetched:
    stored: StoredSample
    final_url: str
    status_code: int
    headers: dict[str, str]
    #: Filename derived from Content-Disposition or the URL path. Untrusted.
    suggested_name: str


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
        # IPv4-mapped IPv6 (::ffff:127.0.0.1) is the classic bypass.
        or (isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None
            and not _is_public(str(addr.ipv4_mapped)))
    )


def _resolve_public(host: str) -> list[str]:
    """Every address `host` resolves to, all of which must be public.

    Checking only the first result is a DNS-rebinding hole: a name can return
    one public and one private address and the client may pick either.
    """
    if host.lower() in _METADATA_HOSTS:
        raise UnsafeURL(f"{host} is a cloud metadata endpoint")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise UnsafeURL(f"{host} does not resolve") from exc

    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise UnsafeURL(f"{host} does not resolve")
    for address in addresses:
        if not _is_public(address):
            raise UnsafeURL(
                f"{host} resolves to {address}, which is inside a private or reserved range"
            )
    return addresses


def _validate(url: str) -> tuple[str, list[str]]:
    """Validate a URL and return its host together with the addresses it resolved to.

    The addresses are returned rather than looked up again by the caller because
    a second lookup reopens the rebinding window this whole module exists to
    close: the connection must go to the very addresses that were checked.
    """
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeURL(f"only http and https are fetched, not {parsed.scheme or 'a bare path'}")
    if not parsed.hostname:
        raise UnsafeURL("the URL has no host")
    if parsed.port is not None and parsed.port not in (80, 443, 8080, 8443):
        raise UnsafeURL(f"port {parsed.port} is not fetched")
    return parsed.hostname, _resolve_public(parsed.hostname)


def assert_safe(url: str) -> str:
    """Validate a URL and return the host. Raises UnsafeURL if it must not be fetched."""
    return _validate(url)[0]


def _pinned_request(client: httpx.Client, url: str, host: str, address: str) -> httpx.Request:
    """A GET aimed at the validated `address` but still addressed to `host`.

    ``Host`` keeps virtual-hosted servers answering with the right site, and
    ``sni_hostname`` keeps TLS negotiating — and verifying the certificate —
    against the hostname rather than the IP literal, so pinning costs no
    certificate strictness.
    """
    original = httpx.URL(url)
    return client.build_request(
        "GET",
        original.copy_with(host=address),
        headers={"Host": original.netloc.decode("ascii")},
        extensions={"sni_hostname": host},
    )


class _BodyReader:
    """File-like view over a streamed response, for ``store_stream``.

    ``response.content`` buffers the whole body before any cap can be applied —
    an audit pushed 803 MB of heap through a 32 MB limit that way. Reading the
    body in chunks lets storage hash and cap it as it arrives and abort the
    transfer the moment the limit is passed.
    """

    def __init__(self, response: httpx.Response) -> None:
        self._chunks = response.iter_bytes()
        self._buffer = b""

    def read(self, size: int = -1) -> bytes:
        while size < 0 or len(self._buffer) < size:
            try:
                self._buffer += next(self._chunks)
            except StopIteration:
                break
        if size < 0:
            taken, self._buffer = self._buffer, b""
            return taken
        taken, self._buffer = self._buffer[:size], self._buffer[size:]
        return taken


def _suggested_name(url: str, headers: httpx.Headers) -> str:
    disposition = headers.get("content-disposition", "")
    if "filename=" in disposition:
        raw = disposition.split("filename=", 1)[1].strip().strip('";')
        # Attacker-controlled: flatten anything path-like. This is metadata; it
        # never becomes a path (see storage.py — samples are content-addressed).
        candidate = raw.replace("\\", "/").rsplit("/", 1)[-1]
        if candidate:
            return candidate[:255]
    path = urlparse(url).path
    return (path.rsplit("/", 1)[-1] or "download")[:255]


def fetch(url: str, *, max_bytes: int = MAX_SAMPLE_BYTES) -> Fetched:
    """Download a sample, re-validating and re-pinning every redirect hop.

    Redirects are followed manually rather than by httpx, because httpx would
    follow a 302 from a permitted host into `http://127.0.0.1:8000/` without
    consulting us again.
    """
    current = url
    last_error: Exception | None = None

    for attempt in range(RETRIES):
        try:
            with httpx.Client(
                follow_redirects=False,
                timeout=TIMEOUT_SECONDS,
                headers={"User-Agent": "Cyclowareness-Sandbox/1.0 (+security analysis)"},
            ) as client:
                for _hop in range(MAX_REDIRECTS + 1):
                    host, addresses = _validate(current)
                    request = _pinned_request(client, current, host, addresses[0])

                    # stream=True: the body is pulled chunk by chunk so the cap
                    # can stop it, and closed in `finally` so a refused or
                    # oversized transfer drops the connection instead of
                    # draining into memory.
                    response = client.send(request, stream=True)
                    try:
                        if response.is_redirect:
                            location = response.headers.get("location")
                            if not location:
                                raise FetchFailed("redirect without a Location header")
                            current = str(httpx.URL(current).join(location))
                            continue

                        if response.status_code != 200:
                            raise FetchFailed(f"server answered {response.status_code}")

                        declared = response.headers.get("content-length")
                        if declared and declared.isdigit() and int(declared) > max_bytes:
                            raise SampleTooLarge(max_bytes)

                        stored = store_stream(_BodyReader(response), max_bytes=max_bytes)
                        return Fetched(
                            stored=stored,
                            final_url=current,
                            status_code=response.status_code,
                            # Kept for threat-intel enrichment: server banners and
                            # content types are weak but real indicators.
                            headers={
                                k.lower(): v
                                for k, v in response.headers.items()
                                if k.lower()
                                in {
                                    "content-type",
                                    "content-length",
                                    "server",
                                    "last-modified",
                                    "etag",
                                    "content-disposition",
                                }
                            },
                            suggested_name=_suggested_name(current, response.headers),
                        )
                    finally:
                        response.close()
                raise FetchFailed(f"more than {MAX_REDIRECTS} redirects")

        except (UnsafeURL, SampleTooLarge):
            raise  # never retried — the answer will not change
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            current = url  # restart the redirect chain on retry

    raise FetchFailed(f"could not download after {RETRIES} attempts: {last_error}")
