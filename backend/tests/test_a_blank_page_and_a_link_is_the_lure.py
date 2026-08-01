"""A tax form is not a dropper, and a page built to be clicked is not clean.

Measured against 45 real malicious PDFs and 20 ordinary documents — ten fillable
IRS forms, four arXiv papers, three NIST publications, the consolidated GDPR
text and a 122-page conference deck. Before this, the PDF analyzer flagged 6 of
40 malicious samples and **11 of 18** ordinary ones. The two signals doing the
accusing were:

* `pdf.javascript`, `high`, on the presence of `/JS`. Present in 3 of 45
  malicious samples and 12 of 20 ordinary ones — a signal firing four times more
  often on the benign side.
* `pdf.embedded_file`, `high` and mapped to the `dropper` capability, on the
  presence of an `/EmbeddedFile` entry. Present in **0** of 45 malicious samples
  and 10 of 20 ordinary ones, every one of them a fillable form carrying the XFA
  data it is made of. Precision zero.

The malicious population has no payload to find: it is link lures, and the
payload is on the far end of the link. So the accusation moved to what is
actually observable about a lure — a page whose entire surface is one click
target, a document that renders nothing at all, and a script whose only job is
to tell the reader to open the file somewhere else.

These tests pin the numbers, in both directions. The false-positive assertions
matter as much as the detection ones: this analyzer has been wrong in that
direction before, and the fix is only a fix if it stays fixed.
"""
from __future__ import annotations

import zlib

import pytest

from app.engine import capabilities
from app.engine.analyzers import pdf as pdf_mod
from app.engine.contracts import Sample


def _pdf(tmp_path, body: bytes, name: str = "s.pdf") -> Sample:
    path = tmp_path / name
    path.write_bytes(body)
    return Sample(
        path=str(path),
        size_bytes=len(body),
        sha256="0" * 64,
        md5="0" * 32,
        mime="application/pdf",
        magic="PDF document",
        claimed_extension=".pdf",
        original_name=name,
        extension_mismatch=False,
        family="pdf",
    )


def _ids(result) -> dict[str, str]:
    return {s.id: s.severity for s in result.signals}


#: A one-page document whose single link annotation covers the whole MediaBox.
#: This is the shape of seven of the 45 measured malicious samples exactly.
def _lure(uri: bytes = b"https://example.invalid/invoice.pdf", rect: bytes = b"0 0 595 842") -> bytes:
    return (
        b"%PDF-1.7\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]/Annots[4 0 R]>>endobj\n"
        b"4 0 obj<</Type/Annot/Subtype/Link/Rect[" + rect + b"]/A 5 0 R>>endobj\n"
        b"5 0 obj<</Type/Action/S/URI/URI(" + uri + b")>>endobj\n"
        b"trailer<</Root 1 0 R>>\nstartxref\n0\n%%EOF\n"
    )


def test_a_link_the_size_of_the_page_is_reported(tmp_path) -> None:
    result = pdf_mod.analyze(_pdf(tmp_path, _lure()))
    signals = _ids(result)
    assert signals.get("pdf.page_is_one_click_target") == "high", signals
    cover = result.facts["page_layout"]["largest_annotation_cover"]
    assert cover == pytest.approx(1.0, abs=0.01), result.facts["page_layout"]


def test_an_ordinary_link_on_ordinary_words_is_not(tmp_path) -> None:
    """The same document with the link on a phrase instead of the page.

    The largest annotation in any of the twenty ordinary documents measured
    covers 38% of its page; this one covers under 2%. If this ever fires, the
    threshold has been moved to somewhere a real document lives.
    """
    result = pdf_mod.analyze(_pdf(tmp_path, _lure(rect=b"100 700 220 720")))
    assert "pdf.page_is_one_click_target" not in _ids(result)


def test_a_full_page_annotation_that_goes_nowhere_is_not_a_lure(tmp_path) -> None:
    """Coverage alone is not the claim -- leaving the machine is half of it.

    A page-sized annotation with no external action is a form field or a
    background widget, which is what the 38% benign maximum turned out to be.
    """
    body = _lure().replace(b"/S/URI/URI(https://example.invalid/invoice.pdf)", b"/S/GoTo/D[0/Fit]")
    assert b"/URI" not in body
    result = pdf_mod.analyze(_pdf(tmp_path, body))
    assert "pdf.page_is_one_click_target" not in _ids(result)


def test_a_document_that_renders_nothing_reports_the_shape_but_does_not_accuse(tmp_path) -> None:
    """`medium`, and NO capability, on purpose.

    A poster whose text was flattened to outlines on export renders zero
    characters and carries a link too, and no such document exists in the benign
    corpus this was measured against — so the evidence for a stronger claim is
    not there. It contributes to the score and it is visible in the report; it
    does not accuse on its own.
    """
    result = pdf_mod.analyze(_pdf(tmp_path, _lure(rect=b"100 700 220 720")))
    signals = _ids(result)
    assert signals.get("pdf.page_renders_no_text") == "medium", signals
    assert "pdf.page_renders_no_text" not in capabilities.CAPABILITY_SIGNALS["deception"]
    for name, ids in capabilities.CAPABILITY_SIGNALS.items():
        assert "pdf.page_renders_no_text" not in ids, name


def test_the_page_shape_signals_assert_deception(tmp_path) -> None:
    deception = capabilities.CAPABILITY_SIGNALS["deception"]
    assert "pdf.page_is_one_click_target" in deception
    assert "pdf.reader_incompatible_lure" in deception


# --- the script -------------------------------------------------------------


def _with_script(script: bytes) -> bytes:
    return (
        b"%PDF-1.7\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R/Names<</JavaScript 6 0 R>>>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]>>endobj\n"
        b"6 0 obj<</S/JavaScript/JS(" + script + b")>>endobj\n"
        b"trailer<</Root 1 0 R>>\nstartxref\n0\n%%EOF\n"
    )


def test_a_form_that_totals_a_column_is_not_accused_of_carrying_script(tmp_path) -> None:
    """The measurement that forced this: 12 of 20 ordinary documents carry
    script, including every fillable IRS form on the list."""
    result = pdf_mod.analyze(_pdf(tmp_path, _with_script(b"AFSimple_Calculate\\('SUM', new Array\\('a'\\)\\);")))
    assert _ids(result).get("pdf.javascript") == "info", _ids(result)


def test_script_that_assembles_code_at_runtime_still_accuses(tmp_path) -> None:
    """The demotion is not a retreat. What a reader exploit needs is still
    `high`, because THAT is the thing a form script never does."""
    result = pdf_mod.analyze(_pdf(tmp_path, _with_script(b"eval\\(unescape\\('%u9090'\\)\\);")))
    signals = _ids(result)
    assert signals.get("pdf.javascript") == "high", signals
    evidence = next(s for s in result.signals if s.id == "pdf.javascript").evidence
    assert "eval(" in evidence["code_building_apis"]


def test_script_inside_a_lure_is_counted_against_it(tmp_path) -> None:
    """Ordinary script in a document that is otherwise a lure is corroborated
    by the page shape, and stops being an aside."""
    body = _lure().replace(
        b"trailer",
        b"9 0 obj<</S/JavaScript/JS(app.alert\\('hi'\\);)>>endobj\ntrailer",
    )
    result = pdf_mod.analyze(_pdf(tmp_path, body))
    signals = _ids(result)
    assert signals.get("pdf.javascript") == "medium", signals


def test_open_action_does_not_accuse_on_script_the_analyzer_discounted(tmp_path) -> None:
    """Two rules of the same file are not allowed to disagree.

    `pdf.open_action` accuses "in the company of script". When the script signal
    became `info` for a fillable form, this gate was still reading the raw
    presence of `/JS` — so /OpenAction stayed `medium` on the strength of a
    finding the analyzer had just declined to count. Ten IRS forms, both ways.
    """
    body = _with_script(b"AFSimple_Calculate\\('SUM', new Array\\('a'\\)\\);").replace(
        b"/Type/Catalog", b"/Type/Catalog/OpenAction[3 0 R /Fit]"
    )
    result = pdf_mod.analyze(_pdf(tmp_path, body))
    signals = _ids(result)
    assert signals.get("pdf.javascript") == "info", signals
    assert signals.get("pdf.open_action") == "info", signals


def test_the_open_in_your_browser_message_is_named(tmp_path) -> None:
    """Three of the 45 malicious samples do this and nothing else with script:
    `app.alert("Unsupported reader! Only PDFs compatible with Chrome.")`."""
    body = _lure().replace(
        b"trailer",
        b"9 0 obj<</S/JavaScript/JS(app.alert\\('Unsupported reader! "
        b"Only PDFs compatible with Chrome.'\\);)>>endobj\ntrailer",
    )
    result = pdf_mod.analyze(_pdf(tmp_path, body))
    assert _ids(result).get("pdf.reader_incompatible_lure") == "high", _ids(result)


def test_half_the_sentence_is_not_the_technique(tmp_path) -> None:
    """"Unsupported" appears in ordinary prose. "Unsupported, so open it in
    your browser" is an instruction, and the instruction is the technique."""
    body = _lure().replace(
        b"trailer",
        b"9 0 obj<</S/JavaScript/JS(app.alert\\('Unsupported file format.'\\);)>>endobj\ntrailer",
    )
    result = pdf_mod.analyze(_pdf(tmp_path, body))
    assert "pdf.reader_incompatible_lure" not in _ids(result)


# --- the attachment ----------------------------------------------------------


def _with_attachment(name: bytes) -> bytes:
    return (
        b"%PDF-1.7\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]>>endobj\n"
        b"7 0 obj<</Type/Filespec/F(" + name + b")/UF(" + name + b")/EF<</F 8 0 R>>>>endobj\n"
        b"8 0 obj<</Type/EmbeddedFile/Length 4>>stream\nMZ\x90\x00\nendstream endobj\n"
        b"trailer<</Root 1 0 R>>\nstartxref\n0\n%%EOF\n"
    )


def test_a_form_carrying_its_own_data_is_not_a_dropper(tmp_path) -> None:
    """0 of 45 malicious samples had an /EmbeddedFile. 10 of 20 ordinary
    documents did. The capability was removed for exactly that reason."""
    result = pdf_mod.analyze(_pdf(tmp_path, _with_attachment(b"form_data.xml")))
    signals = _ids(result)
    assert signals.get("pdf.embedded_file") == "info", signals
    assert "pdf.embedded_executable" not in signals
    assert "pdf.embedded_file" not in capabilities.CAPABILITY_SIGNALS["dropper"]


def test_a_document_carrying_a_program_is_still_a_dropper(tmp_path) -> None:
    """And the other direction, which is the whole point of splitting the id."""
    result = pdf_mod.analyze(_pdf(tmp_path, _with_attachment(b"invoice.exe")))
    signals = _ids(result)
    assert signals.get("pdf.embedded_executable") == "critical", signals
    assert "pdf.embedded_executable" in capabilities.CAPABILITY_SIGNALS["dropper"]


# --- the bounds --------------------------------------------------------------


def test_the_annotation_scan_is_bounded(tmp_path) -> None:
    """A hostile file cannot make the coverage pass expensive: the annotation
    count is capped, and each one looks at a fixed window."""
    body = b"%PDF-1.7\n" + (b"/Subtype/Link/Rect[0 0 10 10]\n" * 20000) + b"%%EOF\n"
    result = pdf_mod.analyze(_pdf(tmp_path, body))
    assert result.ran
    assert result.duration_ms < 10_000, result.duration_ms


def test_a_compressed_lure_is_seen_through_its_streams(tmp_path) -> None:
    """The annotation and the link live in an object stream on a real sample,
    which is why the pass runs over the inflated buffer as well as the raw one."""
    inner = (
        b"<</Type/Annot/Subtype/Link/Rect[0 0 595 842]/A<</S/URI"
        b"/URI(https://example.invalid/x)>>>>"
    )
    body = (
        b"%PDF-1.7\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]>>endobj\n"
        b"4 0 obj<</Type/ObjStm/Filter/FlateDecode>>stream\n"
        + zlib.compress(inner)
        + b"\nendstream endobj\ntrailer<</Root 1 0 R>>\nstartxref\n0\n%%EOF\n"
    )
    result = pdf_mod.analyze(_pdf(tmp_path, body))
    assert _ids(result).get("pdf.page_is_one_click_target") == "high", _ids(result)
