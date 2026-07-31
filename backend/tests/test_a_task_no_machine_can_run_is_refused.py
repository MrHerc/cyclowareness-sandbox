"""A sample no guest can ever run is refused once, not retried forever.

Found live, in CAPE's own scheduler log on the detonation host:

    Task #4063: Failing unserviceable task because no matching machine could be
    found. Requested tags: 'arm'. Available machine tags: {'windows': 2}

Eleven jobs were cycling permanently, one submission every ten seconds, CAPE task
ids climbing past 4068. They are the Sysinternals **ARM64** builds —
`procexp64a.exe`, `Autoruns64a.exe`, `tcpview64a.exe`; `64a` is Microsoft's ARM64
naming. CAPE reads the PE header, tags the task `arm`, finds only Windows x64
guests, and fails it instantly — and will do so identically forever.

The worker reported `ran=False, refused=False`, and `_needs_dynamic` re-offers
anything that neither ran nor was refused. So this is the infinite
re-detonation loop the `refused` marker was added to close, reached through a
different door: last time CAPE said "refused", this time "failed_analysis".

The discriminator is CAPE's own record — `machine` and `started_on` are null when
a task was never given a guest.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

WORKER = Path(__file__).resolve().parents[2] / "worker"


@pytest.fixture()
def cape():
    sys.path.insert(0, str(WORKER))
    try:
        from config import Config  # type: ignore
        from engines.opensource import CapeV2Engine  # type: ignore

        yield CapeV2Engine(
            Config(
                worker_token="t",
                capev2_url="http://127.0.0.1:8000",
                sovereign_mode=True,       # loopback, so not refused as egress
                engine_timeout_seconds=1,
                poll_interval_seconds=0,
                http_timeout_seconds=1,
            )
        )
    finally:
        sys.path.remove(str(WORKER))


class _Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload

    def raise_for_status(self):
        pass


class _Requests:
    """The three CAPE endpoints the engine touches, scripted."""

    def __init__(self, *, status, view):
        self.status = status
        self.view = view
        self.seen = []

    def post(self, url, **kw):
        self.seen.append(url)
        return _Resp({"error": False, "data": {"task_ids": [4063]}})

    def get(self, url, **kw):
        self.seen.append(url)
        if "/tasks/status/" in url:
            return _Resp({"error": False, "data": self.status})
        if "/tasks/view/" in url:
            return _Resp({"error": False, "data": self.view})
        raise AssertionError("unexpected GET " + url)


# The two records, copied from the live deployment.
UNSERVICEABLE = {
    "id": 4063, "status": "failed_analysis", "machine": None,
    "started_on": None, "platform": "windows", "package": "exe",
}
REALLY_RAN_THEN_FAILED = {
    "id": 4064, "status": "failed_analysis", "machine": "cape1",
    "started_on": "2026-07-31 12:10:44", "platform": "windows",
}


def _run(cape, monkeypatch, tmp_path, view):
    import engines.opensource as mod  # type: ignore

    fake = _Requests(status="failed_analysis", view=view)
    monkeypatch.setattr(mod, "_requests", lambda: fake)
    sample = tmp_path / "procexp64a.exe"
    sample.write_bytes(b"MZ" + b"\0" * 64)
    return cape.run(str(sample), "a" * 64, "pe"), fake


def test_a_task_that_never_got_a_machine_is_refused(cape, monkeypatch, tmp_path) -> None:
    """The finding, exactly: terminal, so it must not be offered again."""
    sys.path.insert(0, str(WORKER))
    try:
        report, _ = _run(cape, monkeypatch, tmp_path, UNSERVICEABLE)
    finally:
        sys.path.remove(str(WORKER))

    assert report.ran is False
    assert report.refused is True, "it will fail identically on every future poll"
    assert "machine" in (report.unavailable_reason or "")


def test_a_task_that_started_and_failed_stays_retryable(cape, monkeypatch, tmp_path) -> None:
    """A real analysis failure may well succeed next time — do not burn it."""
    sys.path.insert(0, str(WORKER))
    try:
        report, _ = _run(cape, monkeypatch, tmp_path, REALLY_RAN_THEN_FAILED)
    finally:
        sys.path.remove(str(WORKER))

    assert report.ran is False
    assert report.refused is False


def test_an_unanswerable_probe_errs_toward_retrying(cape, monkeypatch, tmp_path) -> None:
    """If CAPE will not say, the harmless direction is to try again."""
    sys.path.insert(0, str(WORKER))
    try:
        report, _ = _run(cape, monkeypatch, tmp_path, "not-a-dict")
    finally:
        sys.path.remove(str(WORKER))

    assert report.refused is False


def test_the_refusal_marker_is_what_stops_the_loop() -> None:
    """`_needs_dynamic` re-offers anything that neither ran nor was refused —
    which is why `refused` and not merely `ran=False` is the fix."""
    from app.api.dynamic import _needs_dynamic
    from app.engine.models import JobStatus

    class _J:
        family = "pe"
        mime = "application/x-dosexec"
        original_name = "procexp64a.exe"
        archive_path = None
        status = JobStatus.COMPLETED
        tiers = {"dynamic": {"ran": False, "refused": False}}

    job = _J()
    assert _needs_dynamic(job), "the loop: not run, not refused, so offered again"

    job.tiers = {"dynamic": {"ran": False, "refused": True}}
    assert not _needs_dynamic(job)
