"""The report sweep deleted quarantined bytes belonging to jobs it was keeping.

Quarantine is content-addressed: one file backs every job that ever submitted
those bytes. The SAMPLE sweep knows this and holds off --

    if not all(j.created_at and _aware(j.created_at) < cutoff for j in jobs):
        result.samples_retained_shared += 1
        continue

-- unlinking only when every job sharing the hash is old enough, and counting the
times it declined.

The REPORT sweep, forty-five lines below, called `_unlink(job.sha256)` once per
doomed job with no such check. Purging an old report took the bytes a NEWER job
depends on, and that job was not updated: it went on reporting
`sample_deleted_at = NULL` -- "the sample is still held" -- over a file that was
gone. Re-analysis of it fails and `export.signed` cannot re-hash it, which is
the evidence claim being false in the one direction that matters.

Second defect, same loop: `doomed.sort(key=lambda j: j.parent_job_id is None)`
orders one level correctly and two by luck. A zip inside a zip is BOTH a child
and a parent, and nothing put it after its own children -- a foreign-key
violation on PostgreSQL that aborts the whole sweep. Ordering is by depth now.
"""
from __future__ import annotations

import io
import zipfile
from datetime import timedelta

import pytest

from app import retention
from app.config import get_settings
from app.engine import pipeline
from app.engine.models import SandboxJob
from app.engine.storage import quarantine_root, store_bytes
from app.util import utcnow

SHARED = b"the very same bytes, submitted twice, months apart\n" * 40


@pytest.fixture
def policy(monkeypatch):
    """Set a retention policy for one test.

    Settings are cached, so the object is patched rather than the factory --
    the same shape `test_retention.py` uses.
    """
    def _apply(sample_days: int = 0, report_days: int = 0):
        settings = get_settings()
        monkeypatch.setattr(settings, "sample_retention_days", sample_days, raising=False)
        monkeypatch.setattr(settings, "report_retention_days", report_days, raising=False)
        return settings
    return _apply


def _job(db, payload: bytes, name: str, age_days: int) -> SandboxJob:
    job = pipeline.new_job(db, store_bytes(payload), original_name=name, tenant="default")
    job.created_at = utcnow() - timedelta(days=age_days)
    db.commit()
    return job


def _bytes_present(sha256: str) -> bool:
    root = quarantine_root()
    return (root / sha256[:2] / sha256).exists()


def test_purging_an_old_report_keeps_a_newer_jobs_bytes(db, policy) -> None:
    """The finding: two jobs, identical content, only one old enough to purge."""
    old = _job(db, SHARED, "old-copy.txt", age_days=400)
    new = _job(db, SHARED, "new-copy.txt", age_days=1)
    assert old.sha256 == new.sha256, "the point of the test is a shared hash"
    assert _bytes_present(old.sha256)

    policy(sample_days=0, report_days=365)
    retention.sweep(db)
    db.commit()

    assert db.get(SandboxJob, new.id) is not None, "the young job must survive"
    assert _bytes_present(new.sha256), (
        "the young job's evidence was destroyed by another job's report purge"
    )


def test_a_job_whose_bytes_really_are_gone_says_so(db, policy) -> None:
    """The other half: when nothing else needs them, they go."""
    lonely = _job(db, b"nobody else submitted this exact content\n" * 30,
                  "lonely.txt", age_days=400)
    sha = lonely.sha256
    assert _bytes_present(sha)

    policy(sample_days=0, report_days=365)
    retention.sweep(db)
    db.commit()

    assert db.get(SandboxJob, lonely.id) is None
    assert not _bytes_present(sha)


def test_a_nested_archive_is_deleted_deepest_first(db, policy) -> None:
    """A zip inside a zip is both a child and a parent.

    Sorting on `parent_job_id is None` put non-roots first, which orders ONE
    level. The middle zip could still be deleted before its own children, which
    on PostgreSQL is a foreign-key violation that aborts the sweep.
    """
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("payload.txt", b"inner payload for the ordering test\n" * 20)
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("inner.zip", inner.getvalue())

    job = pipeline.new_job(db, store_bytes(outer.getvalue()),
                           original_name="outer.zip", tenant="default")
    db.commit()
    pipeline.run(db, job)
    db.commit()

    everything = [job, *pipeline._descendants(db, job)]
    for row in everything:
        row.created_at = utcnow() - timedelta(days=400)
    db.commit()

    policy(sample_days=0, report_days=365)
    result = retention.sweep(db)
    db.commit()

    assert not result.errors, result.errors
    for row in everything:
        assert db.get(SandboxJob, row.id) is None, f"{row.original_name} survived"


def test_the_sweep_counts_what_it_declined_to_delete(db, policy) -> None:
    """A sweep that holds off must say so; silence reads as "nothing shared"."""
    _job(db, SHARED, "old-a.txt", age_days=400)
    _job(db, SHARED, "new-b.txt", age_days=1)

    policy(sample_days=0, report_days=365)
    result = retention.sweep(db)
    db.commit()
    assert result.samples_retained_shared >= 1
