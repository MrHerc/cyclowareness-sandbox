"""Does the product tell malware apart from software? Measured, on real runs.

`data/detonation_corpus.json` is **93 real detonations** on our own CAPEv2 host:
88 malware from MalwareBazaar and theZoo across 30 family labels, and 5 signed,
current releases downloaded from their vendors. Every signal in it is what the
analyzers actually produced — the dynamic half read back from stored job output,
the static half recomputed with the shipped analyzers — never synthesised.

It replaces an eleven-sample fixture, and the replacement was not a matter of
size alone. Two things about the old one were wrong:

**It did not replay the pipeline.** It fed the dynamic tier's signals alone and
recomputed the score with `ioc_total=0`, so it reproduced verdicts the product
never reached: 57 of 88 where the product gets 72. A fixture that does not
replay the pipeline cannot regression-test it. This one stores every analyzer
the job ran and the score the full pipeline computed.

**Eleven samples said "correct" when they meant "lucky".** Three signed
installers were enough for the benign side, and the thresholds tuned against
them produced a regression where *every* signed installer came out malicious.
Even after that was fixed, the "1 of 5 false positives" figure was measured on a
single re-detonation: on the corpus run the same 7-Zip binary came out
**malicious** and on a rerun the next morning **suspicious**, identical bytes.
Detonation is not deterministic — an unrelated Windows service doing something
during the run becomes evidence — so a corpus of five cannot measure anything.

WHAT THIS FILE ASSERTS, and why in that shape:

* the benign side, **exactly**. A sandbox that flags signed software is worse
  than no sandbox, so those are hard per-sample invariants.
* the malware side, as a **floor** on the aggregate. Individual samples move
  between runs for reasons that are not about our code, and pinning each one
  would make the suite fail for the wrong reason and train people to re-baseline
  it. A drop below the floor is a real regression.

REGENERATING: `infra/detonation-host/regenerate-corpus.py` on the detonation
host. Do not hand-edit the measured numbers to make a run pass.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.engine import capabilities, impact, verdict
from app.engine.contracts import IOCs, AnalyzerResult, Signal

CORPUS = Path(__file__).parent / "data" / "detonation_corpus.json"
DOC = json.loads(CORPUS.read_text(encoding="utf-8"))
SAMPLES = DOC["samples"]
MALWARE = [s for s in SAMPLES if s["kind"] == "malware"]
BENIGN = [s for s in SAMPLES if s["kind"] == "benign"]

#: The floor. Measured, not chosen: it is what the engine scores on this corpus
#: at the commit that generated it, and it may only ever be raised.
#:
#: It is a floor and not an equality because detonation is not reproducible.
#: Raising it after an improvement is correct. Lowering it to make a run pass is
#: how the false-positive regression got in — if a change costs detections, that
#: is a fact to weigh, not a number to edit.
#:
#: Lowered ONCE, from 72, and the reason is written down rather than assumed:
#: `pe.writable_executable_section` stopped asserting the `injection` capability,
#: because a writable+executable section is how every packer works — a fact about
#: how a binary was built, not about what it does to other processes. It cost
#: exactly three samples, all Prometei, whose only accusing capability was that
#: they were packed. It bought back Rufus, a signed and widely-used disk utility
#: that ships UPX-packed and was being called malicious at 64 — and with it the
#: whole class of packed benign software, which is far larger than three samples.
MIN_MALWARE_DETECTED = 69

#: Benign impact ratings, as measured. A ratchet: none may get worse.
#:
#: WinMerge at 7.5 is an OPEN DEFECT, recorded rather than hidden. A signed diff
#: tool should not be rated high-impact, and the capability model still credits
#: it with enough ordinary behaviour (persistence, network, discovery) to get
#: there. It is no longer *malicious*, which was the urgent half.
MAX_BENIGN_CIR = {
    "7z-installer.exe": 6.9,
    "npp-installer.exe": 0.0,
    "putty.exe": 0.0,
    "python.exe": 6.9,
    "winmerge.exe": 7.5,
}


def _results(sample: dict) -> list[AnalyzerResult]:
    """Exactly what the pipeline hands `classify` — every analyzer, not one."""
    return [
        AnalyzerResult(
            analyzer=name,
            ran=analyzer["ran"],
            signals=[
                Signal(
                    id=s["id"], title=s["id"], severity=s["severity"], detail="",
                    evidence=s.get("evidence") or {},
                )
                for s in analyzer["signals"]
            ],
            facts={},
            iocs=IOCs(),
        )
        for name, analyzer in sample["analyzers"].items()
    ]


def _assess(sample: dict) -> dict:
    results = _results(sample)
    signals = [s for r in results if r.ran for s in r.signals]
    return {
        "caps": capabilities.detect(signals),
        "impact": impact.assess("pe", signals, None).to_dict(),
        "verdict": verdict.classify(
            "pe", "application/x-dosexec", results, None, sample["final_score"]
        ).to_dict(),
    }


def _ids(samples):
    return [s["name"] for s in samples]


# --- the corpus is what it claims to be --------------------------------------


def test_the_corpus_is_real_and_wide() -> None:
    assert len(MALWARE) == 88 and len(BENIGN) == 5
    assert len({s["family_label"] for s in MALWARE if s["family_label"]}) >= 25
    for sample in SAMPLES:
        assert sample["analyzers"], f"{sample['name']} has no analyzer output"
        assert sample["analyzers"].get("dynamic.capev2", {}).get("ran"), (
            f"{sample['name']} is in a detonation corpus without a detonation"
        )
        assert sample.get("static_refreshed") is True, (
            f"{sample['name']} carries static signals from an older analyzer"
        )


def test_the_recorded_measurement_matches_the_engine() -> None:
    """The header must not drift from what the code actually does."""
    got = sum(1 for s in MALWARE if _assess(s)["verdict"]["verdict"] == "malicious")
    assert got == DOC["_measured"]["malware_malicious"], (
        f"the corpus header claims {DOC['_measured']['malware_malicious']}/88 "
        f"and the engine produces {got}/88 — regenerate it or explain the change"
    )


# --- the benign side, exactly ------------------------------------------------


@pytest.mark.parametrize("sample", BENIGN, ids=_ids(BENIGN))
def test_no_signed_release_is_called_malicious(sample) -> None:
    """The failure that makes a sandbox unusable: flagging ordinary software."""
    got = _assess(sample)["verdict"]
    assert got["verdict"] != "malicious", f"{sample['name']} -> {got}"


@pytest.mark.parametrize("sample", BENIGN, ids=_ids(BENIGN))
def test_no_signed_release_is_accused_of_a_high_consequence_capability(sample) -> None:
    """Destruction, credential theft, exploitation and injection are accusations."""
    accused = _assess(sample)["caps"] & capabilities.HIGH_CONSEQUENCE
    assert not accused, f"{sample['name']} accused of {sorted(accused)}"


@pytest.mark.parametrize("sample", BENIGN, ids=_ids(BENIGN))
def test_no_engine_fires_on_a_signed_release(sample) -> None:
    """Zero of seven. Anything else is a detection we would have to defend."""
    engines = _assess(sample)["verdict"]["engines"]
    fired = [e["engine"] for e in engines if e["detected"]]
    assert not fired, f"{sample['name']} detected by {fired}"


@pytest.mark.parametrize("sample", BENIGN, ids=_ids(BENIGN))
def test_benign_impact_ratings_do_not_get_worse(sample) -> None:
    ceiling = MAX_BENIGN_CIR[sample["name"]]
    got = _assess(sample)["impact"]["base_score"]
    assert got <= ceiling, f"{sample['name']} rose from {ceiling} to {got}"


# --- the malware side, as a floor --------------------------------------------


def test_the_detection_rate_does_not_regress() -> None:
    caught = [s["name"] for s in MALWARE if _assess(s)["verdict"]["verdict"] == "malicious"]
    assert len(caught) >= MIN_MALWARE_DETECTED, (
        f"{len(caught)}/{len(MALWARE)} detected, floor is {MIN_MALWARE_DETECTED}. "
        "Read the evidence for what changed before touching a threshold."
    )


def test_nothing_malicious_is_called_clean() -> None:
    """Missing a sample is a coverage gap; calling it clean is a wrong answer."""
    clean = [s["name"] for s in MALWARE if _assess(s)["verdict"]["verdict"] == "clean"]
    assert not clean, f"malware rated clean: {clean}"


# --- and the reasons hold up -------------------------------------------------


def test_identification_never_fires_on_a_signed_release() -> None:
    """It fires when the sandbox NAMED the family — an identity claim.

    It used to fire on any high-severity signal the sandbox filed under the
    category "malware", i.e. "a YARA rule matched somewhere in the analysis".
    Measured over eleven samples that looked perfect; measured over this corpus
    it called a signed WinMerge release malicious on `embedded_macho`, a rule
    that fires on three 4-byte magics appearing anywhere in a dump.
    """
    def identified(sample):
        return any(
            e["engine"] == "CS-SandboxID" and e["detected"]
            for e in _assess(sample)["verdict"]["engines"]
        )

    assert not any(identified(s) for s in BENIGN)
    assert sum(1 for s in MALWARE if identified(s)) >= 30


def test_a_named_family_becomes_the_threat_name() -> None:
    """Not a random signal: a real WannaCry run was `Ransom.HardwareIdProfiling`."""
    named = [
        s for s in MALWARE
        if any(
            sig.get("evidence", {}).get("family")
            for a in s["analyzers"].values() for sig in a["signals"]
        )
    ]
    assert named, "no sample in the corpus carries a family identification"
    for sample in named:
        family = next(
            sig["evidence"]["family"]
            for a in sample["analyzers"].values() for sig in a["signals"]
            if sig.get("evidence", {}).get("family")
        )
        token = "".join(c for c in family if c.isalnum())[:20]
        got = _assess(sample)["verdict"]["threat_name"]
        assert token.lower() in got.lower(), f"{sample['name']}: {family} -> {got}"


def test_demonstrated_destruction_is_rated_on_availability() -> None:
    """Where the evidence shows it, the rating must say so — and only there.

    Two samples in this corpus demonstrate a destruction capability (DCRat and
    Stealc, both A:H at 8.3). Exactly two, and no benign sample: `destruction` is
    the accusation this product has been wrongest about, so both halves matter.
    """
    destructive = [s for s in SAMPLES if "destruction" in _assess(s)["caps"]]
    assert destructive, "no sample demonstrates destruction; the corpus lost its teeth"
    assert not [s for s in destructive if s["kind"] == "benign"], (
        f"benign accused of destruction: {[s['name'] for s in destructive if s['kind'] == 'benign']}"
    )
    for sample in destructive:
        rating = _assess(sample)["impact"]
        assert "/A:H" in rating["vector"], f"{sample['name']}: {rating['vector']}"
        assert rating["base_score"] >= 7.0, f"{sample['name']}: {rating['base_score']}"


def test_a_sample_that_barely_ran_is_not_rated_severe() -> None:
    """The corpus's WannaCry produced six dynamic signals and is rated CIR 0.0.

    It is real WannaCry and it did almost nothing — packed, or it did not find
    what it needed. Rating it on its family name rather than on its behaviour
    would be the product inventing evidence, which is the failure mode every
    other test here guards from the opposite direction. A full WannaCry
    detonation IS rated severe; that is `test_wannacry_evidence.py`, against the
    68-signature run.
    """
    wannacry = [s for s in MALWARE if "wannacry" in (s["family_label"] or "").lower()]
    assert wannacry, "the corpus lost its ransomware sample"
    thin = [s for s in wannacry if len(s["analyzers"]["dynamic.capev2"]["signals"]) < 10]
    assert thin, "expected a WannaCry run that barely executed"
    for sample in thin:
        assert _assess(sample)["impact"]["base_score"] == 0.0
