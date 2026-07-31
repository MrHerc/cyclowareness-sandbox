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
        # `_needs_dynamic` reads this; a stub without it models a row that
        # cannot exist.
        sample_deleted_at = None
        status = JobStatus.COMPLETED
        tiers = {"dynamic": {"ran": False, "refused": False}}

    job = _J()
    assert _needs_dynamic(job), "the loop: not run, not refused, so offered again"

    job.tiers = {"dynamic": {"ran": False, "refused": True}}
    assert not _needs_dynamic(job)


# --- the second terminal case: it ran, and the report cannot be built --------

RAN_THEN_REPORTING_FAILED = {
    "id": 4144, "status": "failed_reporting", "machine": "cape3",
    "started_on": "2026-07-31 14:14:24", "platform": "windows",
}


def test_a_report_that_cannot_be_built_is_also_terminal(cape, monkeypatch, tmp_path) -> None:
    """Established by experiment, not assumption.

    A trivial .bat on the same cluster produced status `reported` and a
    528,827-byte report, so CAPE's reporting works. `sample_050.dll` completes
    its analysis on a guest every time and then fails with
    `JsonDump: Recursion limit reached` — its process tree is deep enough to
    exhaust Python's recursion limit, which is a property of the SAMPLE.
    Raising `analysis_call_limit` and enabling `loop_detection` did not touch
    it, because the depth is structural rather than a call count.

    Each retry costs a five-minute guest slot for an identical answer.
    """
    import engines.opensource as mod  # type: ignore

    sys.path.insert(0, str(WORKER))
    try:
        fake = _Requests(status="failed_reporting", view=RAN_THEN_REPORTING_FAILED)
        monkeypatch.setattr(mod, "_requests", lambda: fake)
        sample = tmp_path / "sample_050.dll"
        sample.write_bytes(b"MZ" + b"\0" * 64)
        report = cape.run(str(sample), "b" * 64, "pe")
    finally:
        sys.path.remove(str(WORKER))

    assert report.refused is True
    reason = report.unavailable_reason or ""
    # The two terminal cases mean opposite things about the evidence and must
    # not be described with the same sentence.
    assert "ran to completion" in reason
    assert "not as having found nothing" in reason


def test_a_guest_that_crashed_mid_run_is_still_retried(cape, monkeypatch, tmp_path) -> None:
    """`failed_analysis` WITH a machine is a crash, not the sample's shape."""
    import engines.opensource as mod  # type: ignore

    sys.path.insert(0, str(WORKER))
    try:
        fake = _Requests(status="failed_analysis", view=REALLY_RAN_THEN_FAILED)
        monkeypatch.setattr(mod, "_requests", lambda: fake)
        sample = tmp_path / "x.exe"
        sample.write_bytes(b"MZ")
        report = cape.run(str(sample), "c" * 64, "pe")
    finally:
        sys.path.remove(str(WORKER))

    assert report.refused is False, "a crashed guest may well work next time"


def test_the_terminal_set_excludes_failed_analysis() -> None:
    """It is the one status that means both things, so it is decided by whether
    a machine was ever assigned, never by the word alone."""
    sys.path.insert(0, str(WORKER))
    try:
        from engines.opensource import CapeV2Engine  # type: ignore

        assert "failed_analysis" not in CapeV2Engine._TERMINAL
        assert {"failed_processing", "failed_reporting", "banned"} <= CapeV2Engine._TERMINAL
    finally:
        sys.path.remove(str(WORKER))
