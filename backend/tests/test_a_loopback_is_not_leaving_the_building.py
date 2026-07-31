"""A destination on this machine is not egress.

The sovereignty promise is that analysis data does not leave the deployment.
Both choke points enforced it on the DESTINATION NAME alone, which cannot answer
the question: `capev2` is an upload to a cluster or a loopback call depending
entirely on the URL.

Measured on the reference deployment: `CAPEV2_URL=http://127.0.0.1:8000` — CAPE
on the very same host. Its worker had run since 2026-07-28 on pre-change code, so
detonation still worked; the moment it restarted, `CapeV2Engine.available()`
would have returned False and the dynamic tier would have stopped, with nothing
having been prevented from leaving.

THE RULE, and it must be identical in both processes:

    internal  <- `localhost` / `*.localhost`
              <- a LITERAL IP that is loopback, private or link-local
    external  <- anything else

A hostname is deliberately NOT resolved. Resolution is itself a network call,
the answer can change between the check and the use, and a name that points
somewhere private today can point anywhere tomorrow — so a name is external,
which is the direction that refuses rather than the one that leaks.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from app import sovereignty

WORKER = Path(__file__).resolve().parents[2] / "worker"


@pytest.fixture()
def worker_rule():
    """The worker's own copy of the rule."""
    sys.path.insert(0, str(WORKER))
    try:
        from engines.opensource import _is_internal  # type: ignore

        yield _is_internal
    finally:
        sys.path.remove(str(WORKER))


#: (url, is_internal). The table both implementations are held to.
CASES = [
    # loopback, in the shapes an operator really writes
    ("http://127.0.0.1:8000", True),
    ("http://127.0.0.1", True),
    ("https://localhost:8443/api", True),
    ("http://localhost", True),
    ("http://cape.localhost:8000", True),
    ("http://[::1]:8000", True),
    ("http://127.5.5.5", True),
    # this deployment's own network
    ("http://10.0.0.7:8000", True),
    ("http://192.168.1.50/tasks", True),
    ("http://172.16.4.4:8090", True),
    ("http://[fd00::1]:8000", True),
    ("http://169.254.10.10", True),          # link-local
    # genuinely somewhere else
    ("https://cape.example.com", False),
    ("https://www.virustotal.com/api/v3", False),
    ("http://8.8.8.8:8000", False),
    ("https://[2606:4700::1111]/x", False),
    # a NAME is never resolved, however local it looks
    ("http://cape.internal", False),
    ("http://sandbox.lan:8000", False),
    # nothing at all
    ("", False),
    ("   ", False),
    ("not a url", False),
]


@pytest.mark.parametrize("url,internal", CASES)
def test_the_backend_rule(url, internal) -> None:
    assert sovereignty.destination_is_internal(url) is internal, url


@pytest.mark.parametrize("url,internal", CASES)
def test_the_worker_rule(worker_rule, url, internal) -> None:
    assert worker_rule(url) is internal, url


def test_the_two_processes_cannot_drift(worker_rule) -> None:
    """They share no code, so this is the only thing holding them together."""
    disagreements = [
        u for u, _ in CASES
        if sovereignty.destination_is_internal(u) != worker_rule(u)
    ]
    assert not disagreements, disagreements


# --- what it means at the choke point ----------------------------------------


def test_a_loopback_upload_is_permitted_under_sovereign_mode(monkeypatch) -> None:
    """The finding: CAPE on this host was refused as if it were a cluster."""
    monkeypatch.setattr(sovereignty, "enabled", lambda: True)
    sovereignty.reset()
    # No exception, and nothing recorded — there was nothing to refuse.
    sovereignty.check("capev2", detail="x", url="http://127.0.0.1:8000")
    assert sovereignty.refusals()["total"] == 0


def test_a_remote_upload_is_still_refused(monkeypatch) -> None:
    monkeypatch.setattr(sovereignty, "enabled", lambda: True)
    sovereignty.reset()
    with pytest.raises(sovereignty.OutboundRefused):
        sovereignty.check("capev2", detail="x", url="https://cape.example.com")
    assert sovereignty.refusals()["total"] == 1


def test_a_caller_with_no_url_is_unchanged(monkeypatch) -> None:
    """VirusTotal never passes one; the name alone must still fail closed."""
    monkeypatch.setattr(sovereignty, "enabled", lambda: True)
    sovereignty.reset()
    with pytest.raises(sovereignty.OutboundRefused):
        sovereignty.check("virustotal", detail="sha256 abc")


def test_the_url_fetch_exception_is_not_widened(monkeypatch) -> None:
    """`url_fetch` has its own switch, and a submitted URL pointing at loopback
    must NOT sneak past `SOVEREIGN_ALLOW_URL_FETCH=false` by being local — that
    is a different control, guarding a different thing (the fetcher is also what
    an SSRF would abuse)."""
    monkeypatch.setattr(sovereignty, "enabled", lambda: True)
    monkeypatch.setattr(sovereignty, "url_fetch_allowed", lambda: False)
    sovereignty.reset()
    with pytest.raises(sovereignty.OutboundRefused):
        sovereignty.check(sovereignty.URL_FETCH, url="http://127.0.0.1:9/x")


def test_an_unknown_destination_still_fails_closed(monkeypatch) -> None:
    """Even pointed at loopback: a data path nobody declared stays refused when
    it is remote, and the fail-closed default is the point of the design."""
    monkeypatch.setattr(sovereignty, "enabled", lambda: True)
    sovereignty.reset()
    with pytest.raises(sovereignty.OutboundRefused):
        sovereignty.check("some-new-thing", url="https://elsewhere.example")


# --- and the engine that broke -----------------------------------------------


def test_cape_on_this_host_survives_a_worker_restart(worker_rule) -> None:
    """The exact configuration measured on the reference deployment."""
    sys.path.insert(0, str(WORKER))
    try:
        from config import Config  # type: ignore
        from engines.opensource import CapeV2Engine  # type: ignore

        pytest.importorskip("requests")
        local = Config(
            worker_token="t", capev2_url="http://127.0.0.1:8000", sovereign_mode=True
        )
        assert CapeV2Engine(local).available(), (
            "CAPE on this very host is refused as egress; the dynamic tier stops "
            "the next time the worker restarts"
        )

        remote = Config(
            worker_token="t", capev2_url="https://cape.example.com", sovereign_mode=True
        )
        assert not CapeV2Engine(remote).available()
    finally:
        sys.path.remove(str(WORKER))
