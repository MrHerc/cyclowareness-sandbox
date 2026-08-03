"""`sample_retained` was a claim about policy, not about the disk.

It read `sample_deleted_at is None` and nothing else. That column is stamped by
`retention.sweep`, so on any deployment that never runs a sweep it is NULL for
ever and every export asserted `"sample_retained": true` — unconditionally,
permanently, whatever had happened to the file.

The deployment where that matters is not hypothetical. The portal's blueprint
puts the quarantine on `SANDBOX_QUARANTINE=/tmp/cyclowareness-quarantine` and
says so approvingly — "nothing survives a redeploy" — while its Postgres rows
do survive. So after any redeploy, every JSON, incident, PDF, STIX and signed
export of every earlier job stated that this deployment still held bytes it had
already lost, and the incident record went on inviting a regulator to recompute
the SHA-256 over a file nobody had.

Three states, and the export must tell them apart:

* the bytes are here                          → retained
* a retention sweep deleted them, on a date   → not retained, and we say when
* they are simply gone, no sweep recorded     → not retained, and we say that

The third is new. It is also the only one the portal can currently reach.
"""
from __future__ import annotations

import os
import stat
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.engine import incident, report, storage


def _remove(path: Path) -> None:
    """Delete a quarantined sample from a test.

    `storage._harden` chmods every stored sample to owner-read-only. On POSIX
    that does not prevent deletion — the directory's write bit governs it, so
    CI removes the file happily — but Windows honours the read-only attribute
    and refuses with WinError 5. Restoring write first makes the test say the
    same thing on both, rather than passing on the CI runner and failing on the
    machine it is being written on.
    """
    os.chmod(path, stat.S_IWUSR | stat.S_IRUSR)
    path.unlink()


class _Job:
    """The minimum an export reads. Attribute access only, like the ORM row."""

    def __init__(self, **kw):
        self.sha256 = kw.pop("sha256", "")
        self.sample_deleted_at = kw.pop("sample_deleted_at", None)
        self.status = kw.pop("status", "completed")
        for k, v in kw.items():
            setattr(self, k, v)


@pytest.fixture
def stored(tmp_path, monkeypatch):
    """A real sample on a real quarantine root, and its digest."""
    monkeypatch.setenv("SANDBOX_QUARANTINE", str(tmp_path))
    sample = storage.store_bytes(b"the analysed bytes")
    return sample.sha256


def test_a_sample_on_disk_is_retained(stored):
    job = _Job(sha256=stored)
    assert report._sample_retained(job) is True
    assert report._sample_absent_reason(job) is None


def test_a_sample_the_disk_no_longer_holds_is_not_retained(stored, monkeypatch, tmp_path):
    """The portal's actual state after a redeploy: row present, file gone, no
    sweep ever recorded."""
    path = storage.sample_path(stored)
    assert path is not None and path.is_file()
    _remove(path)

    job = _Job(sha256=stored)
    assert report._sample_retained(job) is False, (
        "the export still claims to hold bytes that are not on the disk"
    )
    reason = report._sample_absent_reason(job)
    assert reason and "retention deletion" in reason
    assert "policy" in reason


def test_a_policy_deletion_is_reported_as_one_not_as_a_loss(stored):
    """Deleting malware on a schedule is correct behaviour and often
    contractual. It must not read as evidence having gone missing."""
    job = _Job(sha256=stored, sample_deleted_at=datetime(2026, 7, 1, tzinfo=timezone.utc))
    assert report._sample_retained(job) is False
    assert report._sample_absent_reason(job) == "deleted under the data-retention policy"


def test_a_job_that_never_stored_anything_is_not_reported_as_lost():
    """A queued, failed or password-parked job has no digest — the incident
    export is total by construction and still produces a record for it. Checking
    the disk for a sample that was never written found nothing and would have
    added a limitation about lost evidence to a record where none was ever
    created."""
    job = _Job(sha256="")
    assert report._sample_retained(job) is True
    assert report._sample_absent_reason(job) is None


def test_a_malformed_digest_never_becomes_a_filesystem_path():
    """`sample_path` is derived from the digest, so a bad one must not be
    allowed to address the disk at all."""
    for bad in ("../../etc/passwd", "zz" * 32, "abc", "", "  "):
        assert storage.sample_path(bad) is None
        assert storage.sample_exists(bad) is False


# --- the incident record, which is the document handed to a regulator --------
def test_the_incident_record_states_the_loss_as_a_limitation(stored):
    _remove(storage.sample_path(stored))
    limitations = incident._evidence(_Job(sha256=stored))["limitations"]
    assert any("not present in this deployment's quarantine" in line for line in limitations), (
        f"the record says nothing about the missing evidence: {limitations}"
    )


def test_the_incident_record_stops_inviting_a_hash_it_cannot_support(stored):
    """The note told the reader to recompute the SHA-256 over the original file.
    Printed while the file is gone, that is an instruction to perform a
    verification this deployment has already made impossible."""
    present = incident._evidence(_Job(sha256=stored))["note"]
    assert "reproduces this record's subject" in present

    _remove(storage.sample_path(stored))
    absent = incident._evidence(_Job(sha256=stored))["note"]
    assert "cannot be recomputed here" in absent
    assert "reproduces this record's subject" not in absent


def test_the_absence_reason_is_a_submission_fact_not_a_reproducible_one(stored):
    """It changes after a sweep, so it must not sit in the half of the signed
    export that claims byte-identity — the same rule `sample_retained` follows,
    and the reason its own test caught this field the moment it was added."""
    from app.engine.attestation import SUBMISSION_KEYS

    assert "sample_absent_reason" in SUBMISSION_KEYS
