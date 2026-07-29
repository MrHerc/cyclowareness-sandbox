"""`invoice.pdf.exe` came back clean.

Windows hides known extensions by default, so a person sees `invoice.pdf` and
double-clicks a program. It is the oldest delivery trick there is, and the check
for it existed only for files found INSIDE an archive or a disk image — the same
file uploaded directly was not looked at. Found by submitting one.

It is NOT `extension_mismatch`: there is no mismatch. The file really is a
`.exe` and the bytes really are a PE. The lie is in the extension before the
last one.

The old test was "three or more dot-separated parts", which is wrong in both
directions. Too loose — `libcurl-x64.dll.a`, `archive.tar.gz` and a man page
called `rclone.1` all have that shape and none is a disguise, which is why five
benign release zips carried `Archive.Dropper.DoubleExtension`. Too tight — it
never asked what the extensions MEAN.

A disguise is: the LAST extension runs, and the one before it reads as something
safe to open.
"""
from __future__ import annotations

import io
import zipfile

import pytest

from app.engine.identify import disguised_name
from tests.test_api import _poll_until_done, _submit

PE = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 4096


@pytest.mark.parametrize("name, looks_like, runs_as", [
    ("invoice.pdf.exe", ".pdf", ".exe"),
    ("photo.jpg.scr", ".jpg", ".scr"),
    ("report.docx.js", ".docx", ".js"),
    ("statement.xlsx.vbs", ".xlsx", ".vbs"),
    ("scan.png.bat", ".png", ".bat"),
    ("backup.zip.exe", ".zip", ".exe"),
    ("INVOICE.PDF.EXE", ".pdf", ".exe"),
    ("holiday.mp4.lnk", ".mp4", ".lnk"),
])
def test_a_disguise_is_recognised(name, looks_like, runs_as) -> None:
    assert disguised_name(name) == (looks_like, runs_as)


@pytest.mark.parametrize("name", [
    "rclone.1",                 # a man page
    "archive.tar.gz",           # .gz does not run
    "libcurl-x64.dll.a",        # .a does not run
    "jquery.min.js",            # .min is not a document extension
    "styles.min.css",
    "app.config.json",
    "tool.exe",                 # one extension is not a disguise
    "notes.txt",
    "",
    ".bashrc",
    "vmlinuz-6.1.0-13-amd64",
])
def test_an_ordinary_name_is_not(name) -> None:
    assert disguised_name(name) is None, name


def test_a_disguised_upload_is_not_clean(client, auth) -> None:
    """The finding itself: the same file, submitted directly."""
    public_id = _submit(client, auth, "invoice.pdf.exe", PE)
    detail = _poll_until_done(client, auth, public_id)
    assert detail["verdict"]["verdict"] != "clean", (
        f"{detail['verdict']['threat_name']} at {detail['final_score']}"
    )
    ids = {
        s["id"]
        for payload in detail["analysis"].values()
        if isinstance(payload, dict)
        for s in payload.get("signals", []) or []
    }
    assert "generic.double_extension" in ids, sorted(ids)


def test_the_same_bytes_honestly_named_are_ordinary(client, auth) -> None:
    """The other end. A program called what it is is not a trick."""
    public_id = _submit(client, auth, "tool.exe", PE)
    detail = _poll_until_done(client, auth, public_id)
    ids = {
        s["id"]
        for payload in detail["analysis"].values()
        if isinstance(payload, dict)
        for s in payload.get("signals", []) or []
    }
    assert "generic.double_extension" not in ids


def test_a_release_zip_of_man_pages_is_not_a_dropper(client, auth) -> None:
    """The regression the loose check caused: five benign release zips were
    `Archive.Dropper.DoubleExtension` for shipping documentation."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("man/rclone.1", "RCLONE(1) manual page\n")
        archive.writestr("lib/libcurl-x64.dll.a", "import library\n")
        archive.writestr("README.txt", "hello\n")
    public_id = _submit(client, auth, "release.zip", buffer.getvalue())
    detail = _poll_until_done(client, auth, public_id)
    assert "DoubleExtension" not in detail["verdict"]["threat_name"], detail["verdict"]


def test_an_archive_hiding_one_is_still_caught(client, auth) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("README.txt", "hello\n")
        archive.writestr("invoice.pdf.exe", PE)
    public_id = _submit(client, auth, "delivery.zip", buffer.getvalue())
    detail = _poll_until_done(client, auth, public_id)
    assert detail["verdict"]["verdict"] != "clean", detail["verdict"]
