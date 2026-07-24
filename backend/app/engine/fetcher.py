"""Fetch a sample from a URL the submitter supplied.

This is the most dangerous function in the engine, and not because of what it
downloads. A server that fetches arbitrary user-supplied URLs is a **Server-Side
Request Forgery** primitive: on a cloud host, `http://169.254.169.254/` is the
instance metadata service and hands out credentials to anyone who asks from
inside the network. "Analyse this URL for me" is exactly the shape of request an
attacker wants a security tool to honour.

So every URL is resolved and checked **before** the connection is made, every
redirect hop is re-checked (a permitted host can 302 into a private address),
and the socket is pinned to the address that was actually validated.
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


def assert_safe(url: str) -> str:
    """Validate a URL and return the host. Raises UnsafeURL if it must not be fetched."""
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeURL(f"only http and https are fetched, not {parsed.scheme or 'a bare path'}")
    if not parsed.hostname:
        raise UnsafeURL("the URL has no host")
    if parsed.port is not None and parsed.port not in (80, 443, 8080, 8443):
        raise UnsafeURL(f"port {parsed.port} is not fetched")
    _resolve_public(parsed.hostname)
    return parsed.hostname


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
    """Download a sample, re-validating every redirect hop.

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
                    assert_safe(current)
                    response = client.get(current)

                    if response.is_redirect:
                        location = response.headers.get("location")
                        if not location:
                            raise FetchFailed("redirect without a Location header")
                        current = str(httpx.URL(current).join(location))
                        response.close()
                        continue

                    if response.status_code != 200:
                        raise FetchFailed(f"server answered {response.status_code}")

                    declared = response.headers.get("content-length")
                    if declared and declared.isdigit() and int(declared) > max_bytes:
                        raise SampleTooLarge(max_bytes)

                    import io

                    stored = store_stream(io.BytesIO(response.content), max_bytes=max_bytes)
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
                raise FetchFailed(f"more than {MAX_REDIRECTS} redirects")

        except (UnsafeURL, SampleTooLarge):
            raise  # never retried — the answer will not change
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            current = url  # restart the redirect chain on retry

    raise FetchFailed(f"could not download after {RETRIES} attempts: {last_error}")
