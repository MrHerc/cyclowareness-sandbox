"""Two things the PDF analyzer said that were not true.

**A document that names /Launch was rated critical for carrying one.** The
keyword is counted over both buffers, and the second is `inflated` -- the
decompressed streams, which is where a PDF's rendered text lives. Demonstrated on
two documents identical but for one sentence of body text:

    "A PDF may carry a /Launch action to start a program."   -> critical
    "A PDF may carry a launch action to start a program."    -> no signals

with the detail "There is no benign authoring tool that emits this." A SOC reads
security papers, spec excerpts and forensic reports; those are the documents this
fires on.

ISO 32000-1 defines the thing as a dictionary whose action-subtype key says so:
`<< /Type /Action /S /Launch /F (cmd.exe) >>`. `/S` is what makes it an action.
Requiring it means the signal fires on structure, not on a word. Prose cannot put
`/S` next to `/Launch`; a real launch action cannot leave it out.

**A PDF over 16 MiB was reported as malformed because only 16 MiB was read.**
`analyze` reads `MAX_SCAN_BYTES`, and `_structure_facts` then checked for
`startxref` -- which is the last thing in a PDF by construction, being the
pointer to the xref table. So every well-formed document over the limit produced
`pdf.parse_failed` at `medium`: "PDF structure is malformed -- the document does
not parse as a well-formed PDF: no startxref". The analyzer already computed
`scan_truncated` into its own facts and never consulted it.

Neither change is a tuned threshold; both are the format's own definitions. That
matters because none of the 40 real malicious PDFs measured for this work carries
a launch action, so there is no positive sample to weigh a heuristic against --
and a specification claim is the only kind of change that is safe without one.
"""
from __future__ import annotations

import hashlib
import zlib

from app.engine import identify
from app.engine.analyzers import pdf as pdf_analyzer
from app.engine.analyzers.pdf import MAX_SCAN_BYTES
from app.engine.contracts import Sample

HEADER = b"%PDF-1.7\n"
TRAILER = b"trailer<</Root 1 0 R>>\nstartxref\n0\n%%EOF\n"


def _analyse(tmp_path, body: bytes):
    path = tmp_path / "doc.pdf"
    path.write_bytes(body)
    ident = identify.identify(str(path), "doc.pdf")
    sample = Sample(
        path=str(path), size_bytes=len(body),
        sha256=hashlib.sha256(body).hexdigest(),
        md5=hashlib.md5(body).hexdigest(),
        mime=ident.mime, magic=ident.magic,
        claimed_extension=ident.claimed_extension, original_name="doc.pdf",
        extension_mismatch=ident.extension_mismatch, family=ident.family,
    )
    result = pdf_analyzer.analyze(sample)
    return {s.id: s for s in result.signals}, result.facts


def _document_saying(sentence: bytes) -> bytes:
    """A PDF whose page content stream renders `sentence`, compressed as usual."""
    stream = zlib.compress(b"BT /F1 12 Tf (" + sentence + b") Tj ET")
    return (
        HEADER
        + b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        + b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        + b"3 0 obj<</Type/Page/Parent 2 0 R/Contents 4 0 R>>endobj\n"
        + b"4 0 obj<</Length " + str(len(stream)).encode()
        + b"/Filter/FlateDecode>>stream\n" + stream + b"\nendstream endobj\n"
        + TRAILER
    )


# --- /Launch -----------------------------------------------------------------

def test_a_paper_naming_the_action_is_not_accused(tmp_path) -> None:
    signals, _ = _analyse(
        tmp_path, _document_saying(b"A PDF may carry a /Launch action to start a program."))
    assert "pdf.launch_action" not in signals, signals.get("pdf.launch_action")


def test_the_same_document_without_the_slash_was_always_fine(tmp_path) -> None:
    """The control: this is what the two documents differ by."""
    signals, _ = _analyse(
        tmp_path, _document_saying(b"A PDF may carry a launch action to start a program."))
    assert "pdf.launch_action" not in signals


def test_a_real_launch_action_is_still_critical(tmp_path) -> None:
    """`<< /Type /Action /S /Launch /F (cmd.exe) >>`, the real thing."""
    body = (
        HEADER
        + b"1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>endobj\n"
        + b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        + b"3 0 obj<</Type/Page/Parent 2 0 R>>endobj\n"
        + b"5 0 obj<</Type/Action/S/Launch/F(cmd.exe)>>endobj\n"
        + TRAILER
    )
    signals, _ = _analyse(tmp_path, body)
    assert "pdf.launch_action" in signals
    assert signals["pdf.launch_action"].severity == "critical"


def test_a_launch_action_hidden_in_a_compressed_stream_is_still_caught(tmp_path) -> None:
    """The inflated buffer must keep working -- that is why it is scanned."""
    inner = zlib.compress(b"<</Type/Action/S/Launch/F(calc.exe)>>")
    body = (
        HEADER
        + b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        + b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        + b"3 0 obj<</Type/Page/Parent 2 0 R>>endobj\n"
        + b"4 0 obj<</Type/ObjStm/N 1/Length " + str(len(inner)).encode()
        + b"/Filter/FlateDecode>>stream\n" + inner + b"\nendstream endobj\n"
        + TRAILER
    )
    signals, _ = _analyse(tmp_path, body)
    assert "pdf.launch_action" in signals, sorted(signals)


def test_the_keyword_count_is_still_recorded(tmp_path) -> None:
    """Not an accusation, but still worth being able to see."""
    _, facts = _analyse(
        tmp_path, _document_saying(b"A PDF may carry a /Launch action to start a program."))
    counts = facts["keyword_counts"]
    assert counts["launch_keyword"] >= 1, counts
    assert counts["launch"] == 0, counts


# --- the read limit ----------------------------------------------------------

def test_a_large_well_formed_pdf_is_not_called_malformed(tmp_path) -> None:
    """`startxref` is the last thing in a PDF; a truncated read never sees it."""
    filler = b"%" + b"p" * 4000 + b"\n"
    padding = filler * ((MAX_SCAN_BYTES // len(filler)) + 8)
    body = (
        HEADER
        + b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        + b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        + b"3 0 obj<</Type/Page/Parent 2 0 R>>endobj\n"
        + padding
        + TRAILER
    )
    assert len(body) > MAX_SCAN_BYTES
    signals, facts = _analyse(tmp_path, body)
    assert facts["scan_truncated"] is True, "the premise of the test"
    reasons = getattr(signals.get("pdf.parse_failed"), "evidence", {}).get("reasons", [])
    assert "no startxref" not in reasons, reasons


def test_a_misplaced_header_is_still_reported(tmp_path) -> None:
    """The checks must not have been switched off, only stopped from lying.

    Under the read limit, so `truncated` is False and every structural check
    still applies. The header sits 200 bytes in, which a reader tolerates and an
    analyst should still be told about.
    """
    body = b"\n" * 200 + HEADER + b"1 0 obj<</Type/Catalog>>endobj\n" + TRAILER
    signals, facts = _analyse(tmp_path, body)
    assert facts["scan_truncated"] is False
    reasons = getattr(signals.get("pdf.parse_failed"), "evidence", {}).get("reasons", [])
    assert any("header" in r for r in reasons), reasons


def test_a_small_pdf_with_no_startxref_is_still_reported(tmp_path) -> None:
    """Under the limit the end WAS read, so the absence is real."""
    body = (
        HEADER
        + b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        + b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        + b"3 0 obj<</Type/Page/Parent 2 0 R>>endobj\n"
        + b"trailer<</Root 1 0 R>>\n%%EOF\n"
    )
    signals, facts = _analyse(tmp_path, body)
    assert facts["scan_truncated"] is False
    reasons = getattr(signals.get("pdf.parse_failed"), "evidence", {}).get("reasons", [])
    assert "no startxref" in reasons, reasons
