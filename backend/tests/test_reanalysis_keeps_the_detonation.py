"""Re-running the cheap tier must not destroy the expensive one.

`pipeline.run` rebuilds its analyzer list from the static analyzers on every
pass, and then writes `job.analysis` wholesale. So a re-analysis — the documented
reason being "e.g. after new YARA rules" — silently dropped the `dynamic.*` entry
a worker had posted.

Reproduced end to end before the fix:

    after static              74.9  high      tiers.dynamic.ran=False
    after detonation ingested 95.2  critical  tiers.dynamic.ran=True
    after RE-ANALYSIS         74.9  high      tiers.dynamic.ran=False
                                              job.dynamic.ran=True   <-- still

`status=completed` and `error=None` throughout. The row ended up asserting both
that the sample was detonated and that it was not, and the score the behaviour
earned was gone.

A detonation costs a guest and several minutes, and it cannot be recovered from
the quarantined bytes without doing it again. It is the most expensive evidence
this product holds, and the cheapest operation in the product was deleting it.
"""
from __future__ import annotations

from tests.test_api import WORKER_TOKEN, _poll_until_done, _submit

REPORT = {
    "engine": "capev2",
    "worker": "detonation-01",
    "ran": True,
    "unavailable_reason": None,
    "refused": False,
    "signals": [
        {
            "id": "capev2.mass_data_encryption", "title": "mass encryption",
            "severity": "high", "detail": "",
            "evidence": {"categories": ["ransomware"]},
        },
        {
            "id": "capev2.deletes_shadow_copies", "title": "shadow copies deleted",
            "severity": "high", "detail": "",
            "evidence": {"categories": ["ransomware"]},
        },
    ],
    "facts": {"task_id": 4242},
    "iocs": {"domains": ["evil.example"]},
    "duration_ms": 50125,
    "timeline": [],
}


def _detonated_job(client, auth) -> tuple[str, dict]:
    public_id = _submit(client, auth, "loader.exe", b"MZ" + b"\x00" * 8192)
    _poll_until_done(client, auth, public_id)
    response = client.post(
        f"/api/dynamic/report/{public_id}",
        json=REPORT,
        headers={"X-Worker-Token": WORKER_TOKEN},
    )
    assert response.status_code == 200, response.text
    return public_id, response.json()


def test_reanalysis_keeps_the_detonation(client, auth) -> None:
    public_id, after_ingest = _detonated_job(client, auth)
    assert after_ingest["tiers"]["dynamic"]["ran"] is True
    assert "dynamic.capev2" in after_ingest["analysis"]
    score_with_behaviour = after_ingest["final_score"]

    assert client.post(f"/api/jobs/{public_id}/reanalyze", headers=auth).status_code == 200
    after = _poll_until_done(client, auth, public_id)

    assert "dynamic.capev2" in after["analysis"], (
        "re-analysis deleted the detonation; it cannot be recovered without "
        "detonating the sample again"
    )
    signals = after["analysis"]["dynamic.capev2"]["signals"]
    assert {s["id"] for s in signals} == {
        "capev2.mass_data_encryption", "capev2.deletes_shadow_copies"
    }
    assert after["final_score"] >= score_with_behaviour - 0.05, (
        f"the score fell from {score_with_behaviour} to {after['final_score']} "
        "because the behavioural evidence was dropped"
    )


def test_the_job_never_contradicts_itself_about_being_detonated(client, auth) -> None:
    """Two fields, one truth. They disagreed, and both were being read."""
    public_id, _ = _detonated_job(client, auth)
    client.post(f"/api/jobs/{public_id}/reanalyze", headers=auth)
    after = _poll_until_done(client, auth, public_id)

    tier_ran = after["tiers"]["dynamic"]["ran"]
    dynamic_ran = (after.get("dynamic") or {}).get("ran")
    assert tier_ran == dynamic_ran is True, (
        f"tiers.dynamic.ran={tier_ran} but dynamic.ran={dynamic_ran}"
    )


def test_a_job_that_was_never_detonated_still_says_so(client, auth) -> None:
    """Carrying the tier forward must not invent one."""
    public_id = _submit(client, auth, "plain.txt", b"nothing to see here\n")
    _poll_until_done(client, auth, public_id)
    client.post(f"/api/jobs/{public_id}/reanalyze", headers=auth)
    after = _poll_until_done(client, auth, public_id)

    assert after["tiers"]["dynamic"]["ran"] is False
    assert "dynamic.capev2" not in after["analysis"]
