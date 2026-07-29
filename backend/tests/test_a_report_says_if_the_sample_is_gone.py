"""Retention deletes the evidence. No document said so.

`retention.sweep` deletes the quarantined bytes and stamps `sample_deleted_at`,
and the only reader of that column anywhere in the application was the dynamic
ingest. So every export went on publishing a SHA-256 — and the incident record
went on telling the reader that "recomputing that hash over the original file
reproduces this record's subject" — for a file this deployment had already
deleted by policy.

"We hold the file" and "we hold a hash of a file we no longer have" are
different claims, and the second one is the honest one after a sweep.

Deleting the malware on a schedule is correct behaviour and is often a
contractual requirement. What is not correct is a regulatory record that invites
a verification step the deployment has made impossible without mentioning it.
"""
from __future__ import annotations

import json

from app.engine.models import SandboxJob
from app.db import session_scope
from tests.test_api import _poll_until_done, _submit

CLEAN = b"# a note\nnothing here\n"


def _purge(public_id: str):
    """What retention.sweep does to the row, without waiting days for it."""
    from datetime import datetime, timezone

    db = session_scope()
    try:
        job = db.query(SandboxJob).filter_by(public_id=public_id).one()
        job.sample_deleted_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.commit()
    finally:
        db.close()


def test_the_json_export_says_the_bytes_are_still_held(client, auth) -> None:
    public_id = _submit(client, auth, "note.txt", CLEAN)
    _poll_until_done(client, auth, public_id)
    body = client.get(f"/api/jobs/{public_id}/export.json", headers=auth).json()
    assert body["sample_retained"] is True
    assert body["sample_deleted_at"] is None


def test_the_json_export_says_when_they_are_not(client, auth) -> None:
    public_id = _submit(client, auth, "note.txt", CLEAN)
    _poll_until_done(client, auth, public_id)
    _purge(public_id)
    body = client.get(f"/api/jobs/{public_id}/export.json", headers=auth).json()
    assert body["sample_retained"] is False
    assert body["sample_deleted_at"], body


def test_the_incident_record_names_it_as_a_limitation(client, auth) -> None:
    """This is the document a regulator reads, and the one that tells them to
    re-hash the original."""
    public_id = _submit(client, auth, "note.txt", CLEAN)
    _poll_until_done(client, auth, public_id)
    _purge(public_id)
    record = client.get(f"/api/jobs/{public_id}/export.incident", headers=auth).json()
    limitations = " ".join(record["evidence"]["limitations"]).lower()
    assert "no longer held" in limitations, record["evidence"]["limitations"]
    assert "retention" in limitations


def test_the_pdf_still_renders_when_the_sample_is_gone(client, auth) -> None:
    public_id = _submit(client, auth, "note.txt", CLEAN)
    _poll_until_done(client, auth, public_id)
    _purge(public_id)
    for name in ("export.pdf", "export.incident", "export.signed", "export.stix"):
        response = client.get(f"/api/jobs/{public_id}/{name}", headers=auth)
        assert response.status_code == 200, name


def test_it_is_a_submission_fact_not_a_reproducible_one(client, auth) -> None:
    """The same sample exported before and after a sweep legitimately differs
    here, so it must not sit in the half that claims byte-identity."""
    public_id = _submit(client, auth, "note.txt", CLEAN)
    _poll_until_done(client, auth, public_id)
    before = client.get(f"/api/jobs/{public_id}/export.signed", headers=auth).json()
    _purge(public_id)
    after = client.get(f"/api/jobs/{public_id}/export.signed", headers=auth).json()

    assert "sample_retained" not in json.dumps(before["report"]["reproducible"])
    assert before["report"]["reproducible_digest"] == after["report"]["reproducible_digest"]
    assert before["report"]["submission"]["sample_retained"] is True
    assert after["report"]["submission"]["sample_retained"] is False
