"""A detonation that landed during a re-analysis was overwritten by it.

`pipeline.run` reads `job.analysis` at the start, carries any `dynamic.*` result
forward, and at the end writes the map it built from that copy. No version
column, no re-read, no row lock. The worker posts reports independently and a
re-analysis takes seconds, so the overlap is ordinary rather than exotic:
`ingest_report` writes the detonation, `run` writes its stale map over the top,
and the detonation is gone -- `tiers.dynamic.ran` back to false, the behavioural
signals lost, and the job offered to the worker again.

The fix is a merge, not a lock, and needs no schema change: keep whichever
dynamic entry RAN. A detonation only ever goes from "not run" to "ran", so
preferring `ran` cannot discard evidence and does not need to know which write
was newer. It is the same principle the tier-carrying code already applies to
`tiers` -- fixed there for this reason, and `analysis` was left behind.
"""
from __future__ import annotations

from sqlalchemy import select

from app.engine import pipeline
from app.engine.models import JobStatus, SandboxJob
from app.engine.storage import store_bytes

SAMPLE = b"# a quiet script\nWrite-Host 'nothing to see'\n"

DETONATION = {
    "ran": True,
    "analyzer": "dynamic.capev2",
    "signals": [
        {"id": "capev2.process_injection", "title": "Injected into a process",
         "severity": "high", "detail": "", "evidence": {}},
    ],
    "facts": {"engine": "capev2"},
    "iocs": {},
}


def _job(db, name: str = "quiet.ps1") -> SandboxJob:
    job = pipeline.new_job(db, store_bytes(SAMPLE), original_name=name, tenant="default")
    db.commit()
    pipeline.run(db, job)
    db.commit()
    assert job.status == JobStatus.COMPLETED
    return job


def _stored(db, job) -> dict:
    value = db.execute(
        select(SandboxJob.analysis).where(SandboxJob.id == job.id)
    ).scalar_one_or_none()
    return value if isinstance(value, dict) else {}


def test_the_premise_a_fresh_run_has_no_detonation(db) -> None:
    job = _job(db)
    assert "dynamic.capev2" not in _stored(db, job)


def test_a_detonation_written_mid_run_is_not_overwritten(db) -> None:
    """The finding, in the order it actually happens.

    The re-analysis has already loaded `job.analysis`; the worker's report lands
    in the database; the re-analysis then writes what it loaded.
    """
    job = _job(db)

    # What ingest_report writes, straight into the column, as another process
    # would. The in-memory `job` object is deliberately NOT updated -- that is
    # the whole situation being reproduced.
    db.execute(
        SandboxJob.__table__.update()
        .where(SandboxJob.id == job.id)
        .values(analysis={**_stored(db, job), "dynamic.capev2": DETONATION})
    )
    db.commit()

    pipeline.run(db, job)
    db.commit()

    kept = _stored(db, job).get("dynamic.capev2")
    assert kept is not None, "the detonation was overwritten by the re-analysis"
    assert kept.get("ran") is True
    assert kept.get("signals"), "its behavioural signals went with it"


def test_a_real_rerun_of_the_detonation_still_replaces_it(db) -> None:
    """The merge must not freeze the first detonation in place.

    `ran` beats `not ran`; a NEWER `ran` result simply replaces the old one,
    because `results` wins whenever both sides ran.
    """
    job = _job(db)
    db.execute(
        SandboxJob.__table__.update()
        .where(SandboxJob.id == job.id)
        .values(analysis={**_stored(db, job), "dynamic.capev2": DETONATION})
    )
    db.commit()
    pipeline.run(db, job)
    db.commit()

    fresher = {**DETONATION, "facts": {"engine": "capev2", "run": "second"}}
    db.execute(
        SandboxJob.__table__.update()
        .where(SandboxJob.id == job.id)
        .values(analysis={**_stored(db, job), "dynamic.capev2": fresher})
    )
    db.commit()
    assert _stored(db, job)["dynamic.capev2"]["facts"]["run"] == "second"


def test_a_static_only_job_is_unaffected(db) -> None:
    """The merge must not invent a dynamic entry where there was none."""
    job = _job(db, "plain.ps1")
    pipeline.run(db, job)
    db.commit()
    assert not any(k.startswith("dynamic.") for k in _stored(db, job))


def test_the_helper_never_raises(db) -> None:
    """A merge that fails must not fail the run it is protecting."""
    class _Detached:
        id = -12345

    assert pipeline._stored_analysis(db, _Detached()) == {}
