"""The chain of custody must not contain records of things that did not happen.

A gap in an audit trail is a known limitation. A FALSE ENTRY is different: it
makes every other entry worth less, because a reader can no longer tell which
ones describe reality. For a product whose argument is "this output is evidence",
that is the failure that matters most.

Two defects, both found by auditing the audit:

**Exports recorded before they authorised.** `_trace` took the raw `public_id`
out of the URL and wrote it, then the lookup ran. So a request for a job
belonging to another tenant — or for a string that was never a job — produced
`REPORT_EXPORTED / outcome=success` in the tamper-evident chain, and bumped the
export metric, for a report that was never generated.

**The dynamic report was invisible.** `AuditAction.DYNAMIC_REPORT_INGESTED` was
defined and had no callers. The largest mutation this product makes to a verdict
— a Formbook sample went `suspicious / Win32.Clean / 32.0` -> `malicious /
Win32.Injector.Formbook / 71.8` on a report posted by an off-host machine — left
no trace at all.
"""
from __future__ import annotations

import io

import pytest

from app import audit
from app.db import session_scope
from tests.test_api import WORKER_TOKEN, _poll_until_done, _submit


def _events(action: str, object_id: str | None = None) -> list:
    db = session_scope()
    try:
        _total, rows = audit.query(db, action=action, object_id=object_id, limit=500)
        return list(rows)
    finally:
        db.close()


# --- exports -----------------------------------------------------------------

EXPORT_ROUTES = [
    "/api/jobs/{id}/export.json",
    "/api/jobs/{id}/export.stix",
    "/api/jobs/{id}/export.incident",
    "/api/jobs/{id}/export.pdf",
]


@pytest.mark.parametrize("route", EXPORT_ROUTES)
def test_an_export_that_did_not_happen_is_not_recorded(client, auth, route) -> None:
    ghost = "11111111-2222-3333-4444-555555555555"
    before = len(_events(audit.AuditAction.REPORT_EXPORTED, ghost))

    response = client.get(route.format(id=ghost), headers=auth)
    assert response.status_code == 404

    after = _events(audit.AuditAction.REPORT_EXPORTED, ghost)
    assert len(after) == before, (
        f"{route} wrote {len(after) - before} export record(s) into the chain of "
        f"custody for a job that does not exist"
    )


def test_a_real_export_is_still_recorded(client, auth) -> None:
    """The other half: refusing to log a lie must not stop logging the truth."""
    public_id = _submit(client, auth, "audited.ps1", b"Write-Host 'hello'\n")
    _poll_until_done(client, auth, public_id)

    before = len(_events(audit.AuditAction.REPORT_EXPORTED, public_id))
    assert client.get(f"/api/jobs/{public_id}/export.json", headers=auth).status_code == 200
    after = _events(audit.AuditAction.REPORT_EXPORTED, public_id)
    assert len(after) == before + 1
    assert after[-1].outcome == audit.AuditOutcome.SUCCESS


# --- the dynamic report ------------------------------------------------------


def test_ingesting_a_dynamic_report_is_recorded(client, auth) -> None:
    public_id = _submit(client, auth, "loader.exe", b"MZ" + b"\x00" * 4096)
    _poll_until_done(client, auth, public_id)

    before = len(_events(audit.AuditAction.DYNAMIC_REPORT_INGESTED, public_id))
    response = client.post(
        f"/api/dynamic/report/{public_id}",
        json={
            "engine": "capev2", "worker": "detonation-01", "ran": True,
            "unavailable_reason": None, "refused": False,
            "signals": [{
                "id": "capev2.mass_data_encryption", "title": "mass encryption",
                "severity": "high", "detail": "",
                "evidence": {"categories": ["ransomware"]},
            }],
            "facts": {}, "iocs": {}, "duration_ms": 1000, "timeline": [],
        },
        headers={"X-Worker-Token": WORKER_TOKEN},
    )
    assert response.status_code == 200, response.text

    after = _events(audit.AuditAction.DYNAMIC_REPORT_INGESTED, public_id)
    assert len(after) == before + 1, (
        "a dynamic report changed the verdict and left no entry in the chain"
    )
    event = after[-1]
    assert event.actor_method == "worker"
    assert "detonation-01" in event.actor
    # What changed, not merely that something did.
    for field in ("verdict_before", "verdict_after", "score_before", "score_after"):
        assert field in event.detail, f"{field} missing from {sorted(event.detail)}"


def test_a_refused_report_is_recorded_too(client, auth) -> None:
    """A sandbox refusing a sample is a fact about coverage, and auditable."""
    public_id = _submit(client, auth, "iot.elf", b"\x7fELF" + b"\x00" * 4096)
    _poll_until_done(client, auth, public_id)

    client.post(
        f"/api/dynamic/report/{public_id}",
        json={
            "engine": "capev2", "worker": "detonation-01", "ran": False,
            "unavailable_reason": "CAPE refused the sample: Linux binaries analysis isn't enabled",
            "refused": True, "signals": [], "facts": {}, "iocs": {},
            "duration_ms": 11, "timeline": [],
        },
        headers={"X-Worker-Token": WORKER_TOKEN},
    )
    events = _events(audit.AuditAction.DYNAMIC_REPORT_INGESTED, public_id)
    assert events, "a refusal left no trace"
    assert events[-1].detail.get("refused") is True
    assert "Linux binaries" in (events[-1].detail.get("unavailable_reason") or "")


def test_a_later_detonation_clears_the_refusal_it_replaces(client, auth) -> None:
    """One record must not contradict itself.

    `job.error` was written when a report came back refused and never cleared,
    so a sample refused once carried the refusal string for ever — including
    after a later run detonated it successfully. The report then read as a
    completed detonation, with signals and a raised verdict, beside
    `error: "CAPE refused the sample: Linux binaries analysis isn't enabled"`.

    Reachable today, not hypothetical: 46 jobs on the live deployment hold that
    string, 31 of them ELF, and `_needs_dynamic` gates only the QUEUE —
    `POST /api/dynamic/report/{public_id}` accepts a second report for a job
    that was already refused, with no code change at all.
    """
    public_id = _submit(client, auth, "iot2.elf", b"\x7fELF" + b"\x01" * 4096)
    _poll_until_done(client, auth, public_id)

    refusal = "CAPE refused the sample: Linux binaries analysis isn't enabled"
    client.post(
        f"/api/dynamic/report/{public_id}",
        json={
            "engine": "capev2", "worker": "detonation-01", "ran": False,
            "unavailable_reason": refusal, "refused": True,
            "signals": [], "facts": {}, "iocs": {}, "duration_ms": 11, "timeline": [],
        },
        headers={"X-Worker-Token": WORKER_TOKEN},
    )
    detail = client.get(f"/api/result/{public_id}", headers=auth).json()
    assert refusal in (detail.get("error") or ""), "the refusal must be recorded"

    # The same sample, run again on a worker that CAN detonate it.
    client.post(
        f"/api/dynamic/report/{public_id}",
        json={
            "engine": "capev2", "worker": "detonation-01", "ran": True,
            "unavailable_reason": None, "refused": False,
            "signals": [{"id": "capev2.deletes_files", "title": "removed files",
                         "severity": "low", "detail": "", "evidence": {}}],
            "facts": {}, "iocs": {}, "duration_ms": 90_000, "timeline": [],
        },
        headers={"X-Worker-Token": WORKER_TOKEN},
    )
    detail = client.get(f"/api/result/{public_id}", headers=auth).json()
    assert not detail.get("error"), (
        "a completed detonation still carrying the refusal it replaced: "
        f"{detail.get('error')!r}"
    )
    assert (detail.get("tiers") or {}).get("dynamic", {}).get("ran") is True


def test_the_chain_still_verifies_after_all_of_this(client, auth) -> None:
    db = session_scope()
    try:
        result = audit.verify_chain(db)
    finally:
        db.close()
    assert result["ok"], result


def test_handing_the_sample_to_the_worker_is_recorded(client, auth) -> None:
    """The only point at which a sample LEAVES this platform.

    Everything else in the chain records what was done to the evidence in place.
    This copies the raw bytes to another machine, and it was the one action not
    written down — "was this sample ever copied off the platform, and where to"
    had no answer but an nginx log.
    """
    public_id = _submit(client, auth, "leaving.exe", b"MZ" + b"\x00" * 4096)
    _poll_until_done(client, auth, public_id)

    before = len(_events(audit.AuditAction.SAMPLE_RELEASED_TO_WORKER, public_id))
    response = client.get(
        f"/api/dynamic/sample/{public_id}", headers={"X-Worker-Token": WORKER_TOKEN}
    )
    assert response.status_code == 200, response.text

    after = _events(audit.AuditAction.SAMPLE_RELEASED_TO_WORKER, public_id)
    assert len(after) == before + 1, "the sample left the platform with no record"
    assert after[-1].detail.get("sha256")


def test_the_evidence_copy_export_is_recorded(client, auth) -> None:
    """export.signed did not take `request`, so it could not audit and never did.

    It is the copy handed to a regulator or opposing counsel — the one export
    whose entire purpose is to be shown to someone who does not trust us.
    """
    public_id = _submit(client, auth, "for-counsel.ps1", b"Write-Host 'x'\n")
    _poll_until_done(client, auth, public_id)

    before = len(_events(audit.AuditAction.REPORT_EXPORTED, public_id))
    assert client.get(f"/api/jobs/{public_id}/export.signed", headers=auth).status_code == 200
    after = _events(audit.AuditAction.REPORT_EXPORTED, public_id)
    assert len(after) == before + 1
    assert after[-1].detail.get("format") == "signed"
