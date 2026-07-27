"""Data-lifecycle regression guard.

Before this existed, ``purge_older_than`` was defined and never called from
anywhere: the quarantine grew until the disk filled, which at a customer site is
an outage. It also decided purely on file mtime, which is wrong for a
content-addressed store — one file backs every job that submitted those exact
bytes, so age alone will delete data a live job still depends on.

These tests pin the four properties that make retention safe to switch on.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app import audit, retention
from app.config import get_settings
from app.engine import pipeline, storage
from app.engine.models import SandboxJob
from app.util import utcnow


@pytest.fixture
def policy(monkeypatch):
    """Set a retention policy for one test. Settings are cached, so patch the object."""
    def _apply(sample_days: int = 0, report_days: int = 0):
        settings = get_settings()
        monkeypatch.setattr(settings, "sample_retention_days", sample_days, raising=False)
        monkeypatch.setattr(settings, "report_retention_days", report_days, raising=False)
        return settings
    return _apply


def _job(db, name: str, data: bytes, *, age_days: float = 0.0) -> SandboxJob:
    stored = storage.store_bytes(data)
    job = pipeline.new_job(db, stored, original_name=name)
    if age_days:
        job.created_at = utcnow() - timedelta(days=age_days)
    db.commit()
    return job


def _bytes_present(sha256: str) -> bool:
    return (storage.quarantine_root() / sha256[:2] / sha256).is_file()


def test_unconfigured_retention_deletes_nothing(db, policy):
    """An unset policy must never delete a customer's evidence."""
    policy(sample_days=0, report_days=0)
    job = _job(db, "old.txt", b"an ancient file", age_days=9999)

    result = retention.sweep(db)

    assert result.ran is False
    assert result.samples_deleted == 0
    assert _bytes_present(job.sha256)


def test_expired_sample_bytes_go_but_the_report_stays(db, policy):
    """The normal steady state: the malware is gone, the evidence remains."""
    policy(sample_days=30, report_days=0)
    job = _job(db, "old.ps1", b"Write-Host 'aged out'", age_days=60)
    sha = job.sha256

    result = retention.sweep(db)

    # The suite shares one database, so other tests' aged rows may be swept in
    # the same pass. Assert on the job this test owns, never on a global count.
    assert result.samples_deleted >= 1
    assert result.bytes_reclaimed > 0
    assert not _bytes_present(sha), "quarantined bytes should be gone"
    db.refresh(job)
    assert job.sample_deleted_at is not None, "the report must record that the file went"
    assert db.get(SandboxJob, job.id) is not None, "the report itself must survive"


def test_a_shared_hash_is_kept_while_any_job_is_in_window(db, policy):
    """The property file-age alone gets wrong.

    Two submissions of identical bytes are one file. Deleting it because the
    older job expired would pull the sample out from under the newer one.
    """
    policy(sample_days=30, report_days=0)
    payload = b"identical bytes submitted twice"
    old = _job(db, "old.bin", payload, age_days=60)
    recent = _job(db, "recent.bin", payload, age_days=1)
    assert old.sha256 == recent.sha256, "content-addressed storage should dedupe these"

    result = retention.sweep(db)

    # Other tests' aged rows may be swept in the same pass (one shared database),
    # so the assertion is about THIS hash: it was held back, and its bytes remain.
    assert result.samples_retained_shared >= 1
    assert _bytes_present(old.sha256), "bytes a live job still references must survive"
    db.refresh(old)
    db.refresh(recent)
    assert old.sample_deleted_at is None
    assert recent.sample_deleted_at is None


def test_expired_report_is_deleted_and_receipted(db, policy):
    policy(sample_days=0, report_days=90)
    job = _job(db, "ancient.txt", b"long past its window", age_days=200)
    job_id, sha = job.id, job.sha256

    result = retention.sweep(db)

    assert result.reports_deleted >= 1
    assert db.get(SandboxJob, job_id) is None
    assert not _bytes_present(sha), "the bytes go with the report"


def test_every_deletion_is_written_to_the_chain_of_custody(db, policy):
    """A deletion nobody can prove happened is not one an auditor accepts."""
    policy(sample_days=30, report_days=0)
    job = _job(db, "aged.ps1", b"aged out for the receipt test", age_days=60)

    before, _ = audit.query(db, limit=1)
    retention.sweep(db, actor="test-operator")

    total, purges = audit.query(
        db, action=audit.AuditAction.SAMPLE_PURGED, object_id=job.sha256, limit=50
    )
    assert total >= 1, "a sample purge must appear in the chain"
    assert purges[0].object_id == job.sha256
    assert purges[0].actor == "test-operator"
    after, _ = audit.query(db, limit=1)
    assert after > before

    assert audit.verify_chain(db)["ok"] is True, "the chain must still verify after a sweep"


def test_policy_is_reported_for_procurement(policy):
    """/api/capabilities carries this; a buyer asks what happens to their data."""
    policy(sample_days=7, report_days=365)
    stated = retention.policy()

    assert stated["enabled"] is True
    assert stated["sample_retention_days"] == 7
    assert "7 days" in stated["statement"]
    assert "365 days" in stated["statement"]


def test_admin_can_sweep_on_demand(client, auth, policy):
    policy(sample_days=30, report_days=0)
    response = client.post("/api/admin/retention/run", headers=auth)

    assert response.status_code == 200
    assert "samples_deleted" in response.json()


def test_api_key_cannot_trigger_a_sweep(client):
    """Retention destroys evidence; a submit-only key must not reach it."""
    assert client.post(
        "/api/admin/retention/run", headers={"X-API-Key": "demo-key"}
    ).status_code in (401, 403)
