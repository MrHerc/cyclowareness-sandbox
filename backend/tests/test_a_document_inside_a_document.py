"""Five malicious DOCX produced nothing, and the evidence was in the part list.

`docx 0/5` in the type-diverse corpus. Identification was right --
`family=office` -- and the analyzer ran and found nothing. Opening the five by
hand shows two techniques, both visible without parsing a single XML node.

**Three carry another document inside them.** Formbook's largest part is
`word/Noyv.rtf` at 5.1 MB; the two WeedHack samples are `word/ubage.rtf` (3.5 MB)
and `word/udio.rtf` (3.1 MB). The .docx is an envelope and the RTF is the
payload. `_ooxml_relationships_and_body` counted a part as embedded only when its
path was under `/embeddings/` or contained `oleobject`, so a document dropped
straight into `word/` was invisible.

**Two are deliberately unreadable.** Both SideWinder samples have a
`word/_rels/document.xml.rels` that Python's zipfile cannot open, inside an
archive whose every other part is perfect. Word is tolerant and reads it; tools
are not, which is the whole point. The loop said `except Exception: continue` --
it saw the technique and swallowed it.

Measured after: **5 of 5**, from 0 of 5. And the benign side unchanged -- a plain
Word document 1.7, a document with a media image 1.7, and a document with a
legitimately embedded Excel chart still 8.3 on the existing
`office.embedded_object`, which this commit does not touch.
"""
from __future__ import annotations

import hashlib
import io
import zipfile

import pytest

from app.engine import identify, scoring
from app.engine.analyzers import run_all
from app.engine.contracts import Sample

BODY = "<w:document><w:body><w:p>Quarterly report.</w:p></w:body></w:document>"


def build(extra: list[tuple[str, bytes]] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        archive.writestr("_rels/.rels", "<Relationships/>")
        archive.writestr("word/document.xml", BODY)
        archive.writestr("word/styles.xml", "<w:styles/>")
        archive.writestr("word/theme/theme1.xml", "<a:theme/>")
        archive.writestr("docProps/core.xml", "<cp:coreProperties/>")
        for name, blob in extra or []:
            archive.writestr(name, blob)
    return buffer.getvalue()


def _analyse(tmp_path, blob: bytes):
    path = tmp_path / "sample.docx"
    path.write_bytes(blob)
    ident = identify.identify(str(path), "sample.docx")
    sample = Sample(
        path=str(path), size_bytes=len(blob),
        sha256=hashlib.sha256(blob).hexdigest(), md5=hashlib.md5(blob).hexdigest(),
        mime=ident.mime, magic=ident.magic, claimed_extension=ident.claimed_extension,
        original_name="sample.docx", extension_mismatch=ident.extension_mismatch,
        family=ident.family,
    )
    results = run_all(sample, sample.family)
    ids = {s.id: s for r in results for s in r.signals}
    return ids, scoring.assess(results, ioc_total=0).final_score


# --- the finding -------------------------------------------------------------

@pytest.mark.parametrize("part", [
    "word/Noyv.rtf",            # Formbook, 5.1 MB in the real sample
    "word/ubage.rtf",           # WeedHack
    "word/payload.doc",
    "word/update.exe",
    "word/loader.hta",
])
def test_a_document_carrying_a_document_is_a_finding(tmp_path, part) -> None:
    ids, score = _analyse(tmp_path, build([(part, b"{\\rtf1" + b"A" * 4000)]))
    assert "office.carries_a_document" in ids, sorted(ids)
    assert ids["office.carries_a_document"].severity == "high"
    assert score > 10


def test_the_carried_part_is_named_in_the_evidence(tmp_path) -> None:
    """An analyst has to be able to see WHICH part, not just that there was one."""
    ids, _ = _analyse(tmp_path, build([("word/Noyv.rtf", b"{\\rtf1" + b"A" * 4000)]))
    evidence = ids["office.carries_a_document"].evidence
    assert any("Noyv.rtf" in p for p in evidence["parts"]), evidence


# --- the benign side, which matters more -------------------------------------

def test_a_plain_document_says_nothing(tmp_path) -> None:
    ids, score = _analyse(tmp_path, build())
    assert not [i for i in ids if i.startswith("office.")], sorted(ids)
    assert score < 5


def test_images_and_fonts_are_not_carried_documents(tmp_path) -> None:
    """Every real document has these; they are parts, not payloads."""
    ids, score = _analyse(tmp_path, build([
        ("word/media/image1.jpeg", b"\xff\xd8\xff" + b"\x00" * 2000),
        ("word/media/image2.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 500),
        ("word/fonts/font1.odttf", b"\x00" * 800),
    ]))
    assert "office.carries_a_document" not in ids
    assert score < 5


def test_a_legitimately_embedded_chart_is_unchanged(tmp_path) -> None:
    """`office.embedded_object` already covers /embeddings/ at medium.

    This commit must not double-count it, or promote it.
    """
    ids, _ = _analyse(tmp_path, build([
        ("word/embeddings/Microsoft_Excel_Sheet1.xlsx", b"PK\x03\x04" + b"\x00" * 40),
    ]))
    assert "office.embedded_object" in ids
    assert ids["office.embedded_object"].severity == "medium"
    assert "office.carries_a_document" not in ids
