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

So the two structural signals become `info` -- weight 0.0, asserts no capability,
still shown in the report. `pdf.open_action` keeps `medium` when JavaScript is
present, a difference the analyzer already recorded in its own evidence: the
/OpenAction that runs script is not the one that sets the opening zoom.

`pdf.uri_action` was already `info` and is left alone. What none of this fixes:
34 of 40 real malicious PDFs are still not caught statically, because they are
link lures with nothing in their bytes to find. That belongs to the detonation
tier and to URL reputation, and it is recorded in
`test_the_floor_only_speaks_for_what_it_covers.py`.
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
    """The three PDFs the analyzer did catch were caught with script present."""
    signals = _signals(tmp_path, WITH_SCRIPT)
    signal = signals.get("pdf.open_action")
    assert signal is not None
    assert signal.severity == "medium", signal.severity
    assert signals.get("pdf.javascript") is not None, "the script itself must fire too"


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
