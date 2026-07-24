"""The SSRF guard: the URL fetcher must refuse to reach anything internal.

A server that downloads user-supplied URLs is an SSRF primitive. These tests pin
the refusals that matter most — loopback, the cloud metadata endpoint, a private
range, and non-HTTP schemes — at the ``assert_safe`` gate, which runs before any
socket is opened, so none of these touch the network.
"""
from __future__ import annotations

import pytest

from app.engine.fetcher import UnsafeURL, assert_safe, fetch


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://127.0.0.1:8080/admin",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://metadata.google.internal/",
        "http://10.0.0.5/internal",  # RFC1918 private
        "http://192.168.1.1/",
        "http://0.0.0.0/",
    ],
)
def test_assert_safe_rejects_internal_addresses(url):
    with pytest.raises(UnsafeURL):
        assert_safe(url)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/x",
        "gopher://example.com/",
        "data:text/plain,hello",
        "/no/scheme/at/all",
    ],
)
def test_assert_safe_rejects_non_http_schemes(url):
    with pytest.raises(UnsafeURL):
        assert_safe(url)


def test_fetch_refuses_before_any_connection():
    # fetch() validates with assert_safe first, so an internal URL raises
    # UnsafeURL without a socket ever being opened.
    with pytest.raises(UnsafeURL):
        fetch("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(UnsafeURL):
        fetch("http://127.0.0.1/")


def test_metadata_host_rejected_by_name_before_resolution():
    # The metadata hostnames are blocked by name, not only by resolved address.
    with pytest.raises(UnsafeURL):
        assert_safe("http://169.254.169.254/")
