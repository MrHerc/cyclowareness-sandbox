"""What happens when the sandbox looks at a sample and says no.

Eight samples from the 107-sample corpus never detonated. CAPE answered

    {"error": true, "error_value": "Error adding task to database"}

and that string was the only record anywhere — CAPE does not log this path, so
the cause looked unexplainable for a day. It was in the response all along, in
the sibling `errors` array the client discarded:

    "errors": [{"<sha>.elf": {"error": "Linux binaries analysis isn't enabled"}}]

Every one of the eight was a Linux ELF binary — Mirai and Gafgyt, ARM, MIPS,
x86-64, Renesas SH. This CAPE has `[linux] enabled = no` in web.conf and three
Windows guests, so it refused them before a task was ever created.

Two things then went wrong in our product, and they are what this file guards.

**The jobs read as finished.** `status = completed`, `error = NULL`, and six of
the eight `risk_level = low`. Live IoT botnet binaries, recorded as completed
low-risk analyses, because a tier that did not run was indistinguishable from a
tier that ran and saw nothing.

**And they never stopped.** `_needs_dynamic` re-offered them on every poll, so
the worker re-downloaded, re-submitted and was re-refused indefinitely. All
eight were still in the live queue when this was found.
"""
from __future__ import annotations

from tests.test_api import WORKER_TOKEN, _poll_until_done, _submit

REFUSAL = "CAPE refused the sample: Error adding task to database: Linux binaries analysis isn't enabled"


def _report(client, public_id: str, **overrides):
    body = {
        "engine": "capev2",
        "worker": "test-worker",
        "ran": False,
        "unavailable_reason": REFUSAL,
        "refused": True,
        "signals": [],
        "facts": {},
        "iocs": {},
        "duration_ms": 11,
        "timeline": [],
    }
    body.update(overrides)
    return client.post(
        f"/api/dynamic/report/{public_id}",
        json=body,
        headers={"X-Worker-Token": WORKER_TOKEN},
    )


def _elf_job(client, auth) -> str:
    public_id = _submit(client, auth, "sample_017.elf", b"\x7fELF" + b"\x00" * 4096)
    _poll_until_done(client, auth, public_id)
    return public_id


def test_a_refusal_is_recorded_on_the_job_not_only_in_the_tier(client, auth) -> None:
    """`error` was NULL on all eight, so nothing in the job said anything."""
    public_id = _elf_job(client, auth)
    response = _report(client, public_id)
    assert response.status_code == 200, response.text

    job = response.json()
    assert job["error"] == REFUSAL, job["error"]
    assert job["tiers"]["dynamic"]["ran"] is False
    assert job["tiers"]["dynamic"]["refused"] is True
    assert "Linux binaries analysis" in job["tiers"]["dynamic"]["detail"]


def test_the_reason_reaches_the_field_the_ui_reads(client, auth) -> None:
    """`job.dynamic` omitted it entirely: `{"ran": false, "signals": []}`."""
    public_id = _elf_job(client, auth)
    job = _report(client, public_id).json()
    assert job["dynamic"]["unavailable_reason"] == REFUSAL
    assert job["dynamic"]["refused"] is True


def test_a_refused_job_is_never_offered_again(client, auth) -> None:
    """The identical request gets the identical answer. Retrying is a loop."""
    public_id = _elf_job(client, auth)
    _report(client, public_id)

    for _ in range(40):
        batch = client.get(
            "/api/dynamic/queue?limit=100", headers={"X-Worker-Token": WORKER_TOKEN}
        ).json()
        if not batch:
            break
        ids = [item["public_id"] for item in batch]
        assert public_id not in ids, "a refused sample was offered for detonation again"
        for other in ids:
            _report(client, other, ran=True, refused=False, unavailable_reason=None)


def test_an_unavailable_engine_is_still_retried(client, auth) -> None:
    """A refusal is terminal; "not right now" must not be.

    A worker whose sandbox is down, or which timed out, has said nothing about
    the sample. Treating that as terminal would silently drop work — the exact
    failure in the other direction.
    """
    public_id = _elf_job(client, auth)
    job = _report(
        client, public_id, refused=False, unavailable_reason="CAPE task 9 did not report within 600s"
    ).json()
    assert job["tiers"]["dynamic"].get("refused") is not True
    assert job["error"] is None

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
            _report(client, other, ran=True, refused=False, unavailable_reason=None)
    raise AssertionError("a job whose engine was merely unavailable was dropped")


def test_a_worker_that_predates_the_field_keeps_retrying(client, auth) -> None:
    """`refused` is absent from an older worker's payload; it must default False."""
    public_id = _elf_job(client, auth)
    body = {
        "engine": "capev2", "worker": "old-worker", "ran": False,
        "unavailable_reason": "something went wrong", "signals": [], "facts": {},
        "iocs": {}, "duration_ms": 1, "timeline": [],
    }
    response = client.post(
        f"/api/dynamic/report/{public_id}", json=body,
        headers={"X-Worker-Token": WORKER_TOKEN},
    )
    assert response.status_code == 200, response.text
    assert response.json()["tiers"]["dynamic"].get("refused") is not True
