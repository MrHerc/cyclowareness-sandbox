"""NIST 800-53 scored higher than nearly every real malicious PDF.

Forty real malicious PDFs were pulled from MalwareBazaar (NetSupport,
Latrodectus, BazaLoader, DarkGate, WikiLoader, Rhadamanthys, AgentTesla,
Grandoreiro, LummaStealer, RemcosRAT, WarmCookie, BumbleBee, ConnectWise,
Gamaredon, UnicornSpy, AsyncRAT, HatefWiper, Fog, ValleyRAT) and put through the
deployed engine. Static tier:

    signal                          flagged   missed
    pdf.uri_action                        3       31
    pdf.open_action                       3        4
    pdf.object_streams                    2        6
    pdf.javascript                        3        0
    generic.extension_mismatch            3        0

Six of forty flagged. Three of those six are not PDFs -- scripts named `.pdf`,
caught by `generic.extension_mismatch`. The PDF analyzer proper caught three,
every one by `pdf.javascript`. **Every flagged sample that carried a structural
signal also carried `pdf.javascript`**, so no structural signal ever
independently caught anything.

Against that, NIST 800-53 reached `suspicious` at 14.1 on `open_action` +
`uri_action` + object streams + `suspicious_tld` and nothing else -- a higher
score than nearly every genuine malicious PDF in the set. After this change it
re-analyses to `clean` at 6.4, and the malicious side is unchanged: the same six,
three by `pdf.javascript` and three by `generic.extension_mismatch`.

A structural discriminator was looked for before any severity was touched, and
there is not one. All forty malicious samples are 1-2 pages, which looks decisive
until the control group includes IRS Form 1040: two pages, entirely legitimate.
Uncompressed content size overlaps in both directions.

    CORRECTION, from a later and wider measurement. "There is not one" was too
    strong a conclusion to draw from two columns. That search compared page
    count and content size; it never asked what the page IS. Two properties do
    separate the populations cleanly, against a control group grown to twenty
    real documents:

        a link annotation covering >=50% of its page     11/45 malicious, 0/20 benign
        pdfminer reads <=40 characters, and it links out 22/45 malicious, 0/20 benign

    The least text in any of the twenty controls is 2,868 characters, and the
    largest annotation in any of them covers 38% of its page. See
    `test_a_blank_page_and_a_link_is_the_lure.py`. The static tier now flags 14
    of 40 rather than 6, and — the more important number — 0 of 18 ordinary
    documents rather than 11.

So the two structural signals become `info` -- weight 0.0, asserts no capability,
still shown in the report. `pdf.open_action` keeps `medium` when JavaScript is
present, a difference the analyzer already recorded in its own evidence: the
/OpenAction that runs script is not the one that sets the opening zoom.

    ALSO CORRECTED. "When JavaScript is present" was the right gate only while
    `pdf.javascript` was itself a `high` on that same presence. It is not: the
    wider measurement put script in 12 of 20 ordinary documents against 3 of 45
    malicious ones. The gate is now "when the script signal is itself counting",
    so a fillable form with an /OpenAction is `info` on both, and a document
    whose script assembles code, or whose page is one link, is `medium` on both.

`pdf.uri_action` was already `info` and is left alone. What none of this fixes:
34 of 40 real malicious PDFs are still not caught statically, because they are
link lures with nothing in their bytes to find. That belongs to the detonation
tier and to URL reputation, and it is recorded in
`test_the_floor_only_speaks_for_what_it_covers.py`.

    PARTLY FIXED SINCE. "Nothing in their bytes to find" was the assumption that
    made the sentence above true, and it was wrong: what a lure has in its bytes
    is the SHAPE of a page meant to be clicked rather than read. Half of them are
    caught statically now. The other half are one-page documents that do render
    some text and put their link on a phrase, and for those the sentence still
    holds — a page with a paragraph and a hyperlink is a page with a paragraph
    and a hyperlink, and no amount of static reading separates the invoice from
    the lure. That half is still the detonation tier's, and still URL
    reputation's, and this is not claimed as solved.
"""
from __future__ import annotations

import hashlib

from app.engine import identify
from app.engine.analyzers import pdf as pdf_analyzer
from app.engine.contracts import Sample
from app.engine.scoring import SEVERITY_WEIGHT


def _signals(tmp_path, body: bytes):
    """Run the analyzer over real bytes on disk and return {id: Signal}.

    Same shape as `_analyse` in test_a_library_is_not_a_dropper.py -- the
    analyzer reads the file, so a stub object would not exercise it.
    """
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
    return {s.id: s for s in pdf_analyzer.analyze(sample).signals}


#: The minimum a reader will accept, with an /OpenAction that only sets the view.
ORDINARY = (
    b"%PDF-1.7\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction[3 0 R /Fit]>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page /Parent 2 0 R>>endobj\n"
    b"trailer<</Root 1 0 R>>\n%%EOF\n"
)

#: The same document, except the action runs script.
WITH_SCRIPT = ORDINARY.replace(
    b"/OpenAction[3 0 R /Fit]",
    b"/OpenAction<</S/JavaScript/JS(app.alert\\(1\\))>>",
)

#: And the same again, with script that assembles code as it runs.
#:
#: The difference matters now. When this file was written `pdf.javascript` was
#: `high` on the presence of `/JS`, so "script is present" and "script counts"
#: were the same statement. A later measurement over 45 malicious PDFs and 20
#: ordinary documents separated them: script is present in 3 of the malicious
#: and 12 of the ordinary ones, including every fillable IRS form.
WITH_EXPLOIT_SCRIPT = ORDINARY.replace(
    b"/OpenAction[3 0 R /Fit]",
    b"/OpenAction<</S/JavaScript/JS(eval\\(unescape\\('%u9090'\\)\\))>>",
)


def test_info_weighs_nothing() -> None:
    """The premise of the change: `info` is visible and costs nothing."""
    assert SEVERITY_WEIGHT["info"] == 0.0
    assert SEVERITY_WEIGHT["medium"] > 0


def test_a_plain_open_action_does_not_accuse(tmp_path) -> None:
    """How 'open at page 1, fit width' is stored. Both NIST documents have one."""
    signal = _signals(tmp_path, ORDINARY).get("pdf.open_action")
    assert signal is not None, "the observation must still be reported"
    assert signal.severity == "info", signal.severity


def test_an_open_action_that_runs_script_still_accuses(tmp_path) -> None:
    """The three PDFs the analyzer did catch were caught with script present.

    The gate moved from "script is present" to "the script signal is itself
    counting", and on those three real samples the answer is unchanged: their
    page is one full-size link, that corroborates the script, and
    `pdf.open_action` is still `medium`. They now score 35.6 rather than 24.2.

    Here the corroboration is the script itself — it assembles code as it runs,
    which is what a reader exploit needs and what a form script never does.
    """
    signals = _signals(tmp_path, WITH_EXPLOIT_SCRIPT)
    signal = signals.get("pdf.open_action")
    assert signal is not None
    assert signal.severity == "medium", signal.severity
    assert signals.get("pdf.javascript") is not None, "the script itself must fire too"
    assert signals["pdf.javascript"].severity == "high"


def test_an_open_action_beside_a_form_script_does_not_accuse(tmp_path) -> None:
    """The other end of the same gate, and the reason it moved.

    A fillable form runs script to total a column and to check the reader's
    version, and three of the ten IRS forms measured also carry an /OpenAction.
    While this gate read the raw presence of `/JS`, that combination was a
    `medium` — an accusation resting entirely on a finding the analyzer had, one
    block earlier, decided was not evidence.
    """
    signals = _signals(tmp_path, WITH_SCRIPT)
    assert signals["pdf.javascript"].severity == "info", "presence alone is not evidence"
    assert signals["pdf.open_action"].severity == "info", signals["pdf.open_action"].severity


def test_object_streams_are_context_not_accusation(tmp_path) -> None:
    """Its own detail text said modern writers do this legitimately."""
    body = b"%PDF-1.7\n" + b"".join(
        b"%d 0 obj<</Type/ObjStm/N 4>>stream\nx\nendstream endobj\n" % n
        for n in range(1, 6)
    ) + b"trailer<</Root 1 0 R>>\n%%EOF\n"
    signal = _signals(tmp_path, body).get("pdf.object_streams")
    if signal is not None:
        assert signal.severity == "info", signal.severity


def test_the_detail_text_no_longer_contradicts_the_severity() -> None:
    """A signal that says "legitimate" while charging for it is a false statement."""
    source = (
        __import__("pathlib").Path(pdf_analyzer.__file__).read_text(encoding="utf-8")
    )
    block = source[source.index("pdf.object_streams"):]
    block = block[: block.index("evidence=")]
    assert 'severity="info"' in block, block[:400]


def test_object_streams_no_longer_assert_an_attack_technique(tmp_path) -> None:
    """`info` was not enough on its own, and this is the part that proved it.

    Demoting the signal stopped it scoring and stopped it granting a capability,
    because `capabilities.detect` refuses anything below `low`. But
    `mitre.map_techniques` has NO severity gate -- it matches on
    `f"{signal.id} {signal.title}"` -- so the word `obfuscation` inside the id
    kept asserting T1027 "Obfuscated Files or Information". Verified on the live
    deployment after the demotion:

        benign_027.pdf  verdict=clean  score=6.4  capabilities: (none)
              MITRE T1027  <- pdf.object_stream_obfuscation

    A clean verdict, no capabilities, and an ATT&CK technique saying the document
    hides itself. So the id changed too.

    A blanket severity gate on `map_techniques` was measured and rejected: it
    would drop 362 techniques across the deployment, 28 on MALICIOUS samples --
    T1105 from `pe.imports.network`, T1056.001 from `pe.imports.keylogging`,
    T1055 from `pe.imports.process_injection`. Weak evidence, but real ATT&CK
    context on a confirmed sample.
    """
    from app.engine.mitre import map_techniques

    body = b"%PDF-1.7\n" + b"".join(
        b"%d 0 obj<</Type/ObjStm/N 4>>stream\nx\nendstream endobj\n" % n
        for n in range(1, 6)
    ) + b"trailer<</Root 1 0 R>>\n%%EOF\n"
    signals = list(_signals(tmp_path, body).values())
    techniques = [t["technique_id"] for t in map_techniques(signals)]
    assert "T1027" not in techniques, (
        f"object streams still assert Obfuscated Files or Information: {techniques}"
    )


def test_object_streams_are_not_an_evasion_capability() -> None:
    """It was listed under `evasion`, next to VBA stomping and packer sections."""
    from app.engine.capabilities import CAPABILITY_SIGNALS

    evasion = CAPABILITY_SIGNALS["evasion"]
    assert "pdf.object_streams" not in evasion
    assert "pdf.object_stream_obfuscation" not in evasion, "the old id, too"
