"""What happens when an operator actually turns the dynamic tier on.

Every other test in this suite runs with `SANDBOX_DYNAMIC_WORKER` unset —
`conftest.py` pops it — so the whole suite only ever exercised the feature being
off. That is why this survived:

`_tier_record` set `dynamic.ran` from the flag rather than from a worker report,
so switching the feature on made every completed job say

    "Detonation, syscall tracing and the native engine ran on an attached
     isolated worker."

about a sample nothing had executed — a false statement in an artifact this
product signs and hands to a regulator. And because `_needs_dynamic` skips jobs
whose dynamic tier already ran, the job was then dropped from the worker queue,
so it never would be detonated. Turning the feature on switched it off and lied
about having done the work.

The invariant these tests hold: **only a worker report may set `dynamic.ran`.**
"""
from __future__ import annotations

import pytest

from app.engine import native
from tests.test_api import WORKER_TOKEN, _poll_until_done, _submit


@pytest.fixture()
def worker_attached(monkeypatch):
    """Declare a worker the way an operator does, and prove the flag is live."""
    monkeypatch.setattr(native, "dynamic_available", lambda: True)
    assert native.dynamic_available() is True
    return True


@pytest.fixture()
def completed_job(client, auth, worker_attached):
    public_id = _submit(client, auth, "loader.exe", b"MZ" + b"\x00" * 8192)
    return public_id, _poll_until_done(client, auth, public_id)


def test_the_pipeline_never_claims_a_detonation_that_has_not_happened(completed_job) -> None:
    _, report = completed_job
    dynamic = report["tiers"]["dynamic"]
    assert dynamic["ran"] is False, (
        "static analysis finished and the report already says the sample was "
        f"detonated: {dynamic}"
    )


def test_the_wording_still_tells_the_operator_a_worker_is_attached(completed_job) -> None:
    """False must not read as "this deployment cannot do dynamic analysis"."""
    detail = completed_job[1]["tiers"]["dynamic"]["detail"].lower()
    assert "queued" in detail or "will be merged" in detail, detail
    assert "ran on an attached" not in detail


def test_the_job_reaches_the_worker_queue(client, completed_job) -> None:
    """The bug's second half: a job marked as run is never offered for running.

    Drained the way a worker drains it, rather than by looking at the head. The
    queue is FIFO and the suite shares one database, so a job created by this
    test sits behind everything earlier tests left waiting — being absent from
    the first page means "there is a backlog", not "it was excluded".
    """
    public_id, _ = completed_job
    for _ in range(40):
        batch = client.get(
            "/api/dynamic/queue?limit=100", headers={"X-Worker-Token": WORKER_TOKEN}
        ).json()
        if not batch:
            break
        ids = [item["public_id"] for item in batch]
        if public_id in ids:
            return
        for other in ids:
            client.post(
                f"/api/dynamic/report/{other}",
                json={"engine": "capev2", "worker": "drain", "ran": True,
                      "unavailable_reason": None, "signals": [], "facts": {},
                      "iocs": {}, "duration_ms": 1, "timeline": []},
                headers={"X-Worker-Token": WORKER_TOKEN},
            )
    raise AssertionError(
        "a detonatable job never reached the queue; with the flag on it would "
        "never be detonated"
    )


def test_only_a_worker_report_flips_the_tier(client, completed_job) -> None:
    public_id, before = completed_job
    assert before["tiers"]["dynamic"]["ran"] is False

    response = client.post(
        f"/api/dynamic/report/{public_id}",
        json={
            "engine": "capev2",
            "worker": "test-worker",
            "ran": True,
            "unavailable_reason": None,
            "signals": [{
                "id": "capev2.mass_data_encryption", "title": "mass encryption",
                "severity": "high", "detail": "",
                "evidence": {"categories": ["ransomware"]},
            }],
            "facts": {},
            "iocs": {},
            "duration_ms": 1000,
            "timeline": [],
        },
        headers={"X-Worker-Token": WORKER_TOKEN},
    )
    assert response.status_code == 200, response.text
    after = response.json()["tiers"]["dynamic"]
    assert after["ran"] is True
    assert after["worker"] == "test-worker"
    assert "capev2" in after["detail"]


def test_a_worker_that_could_not_run_is_recorded_as_not_run(client, completed_job) -> None:
    """`ran=False` from a worker is a first-class answer, not an error."""
    public_id, _ = completed_job
    response = client.post(
        f"/api/dynamic/report/{public_id}",
        json={
            "engine": "capev2", "worker": "test-worker", "ran": False,
            "unavailable_reason": "CAPE task 7 ended as failed_analysis",
            "signals": [], "facts": {}, "iocs": {}, "duration_ms": 0, "timeline": [],
        },
        headers={"X-Worker-Token": WORKER_TOKEN},
    )
    assert response.status_code == 200, response.text
    dynamic = response.json()["tiers"]["dynamic"]
    assert dynamic["ran"] is False
    assert "failed_analysis" in dynamic["detail"]
