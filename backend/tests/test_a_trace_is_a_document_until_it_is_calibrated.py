"""Linux detonation, enabled — and deliberately not believed yet.

The dynamic tier now runs ELF samples. What it produces is recorded, timelined,
carried into the signed evidence, and shown to the analyst. What it does NOT do
is move the number, and that is a measurement rather than caution:

* CAPE loads `modules/signatures/all/` for a Linux task as well as the four in
  `linux/`. `all/stealth_network.py` fires whenever the report has network hosts
  and no `network`-category call was seen — and the strace processor emits
  category `net`, never `network`. It is a GUARANTEED false positive on any
  Linux task with a PCAP, not a no-op.
* `capev2.deletes_files` arrives at CAPE severity 3, which `_CAPE_SEVERITY` maps
  to `high`, on any `unlink` or `O_TRUNC`.
* Not one Linux id appears in `AMBIENT_SIGNALS`, `STRUCTURAL_SIGNALS` or
  `FAMILY_AMBIENT_SIGNALS`, because there is no benign Linux corpus to build
  those lists from the way the 50-sample Windows corpus built them.

So the first flagged Linux sample would most likely have read
`Linux.Backdoor.DeletesFiles` on the evidence that it truncated a file, pushed
over the threshold by the guest's own DNS traffic. That is the false-positive
disease this engine spent a corpus curing on PDF and on static ELF.

These tests hold the line in BOTH directions: the evidence must survive intact,
and it must not accuse. Deleting `DYNAMIC_UNCALIBRATED_FAMILIES` without first
building a benign Linux corpus fails them.
"""
from __future__ import annotations

import pytest

from app.engine import scoring, verdict
from app.engine.contracts import AnalyzerResult, IOCs, Signal


def _dynamic_result(*signals: Signal) -> AnalyzerResult:
    return AnalyzerResult(analyzer="dynamic.capev2", ran=True, signals=list(signals))


DELETES = Signal(
    id="capev2.deletes_files",
    title="Deletes files",
    severity="high",
    detail="unlink() on three paths",
    evidence={},
)
STEALTH = Signal(
    id="capev2.stealth_network",
    title="Network activity without a network call",
    severity="high",
    detail="the guaranteed Linux false positive",
    evidence={},
)


def test_a_linux_detonation_scores_nothing() -> None:
    """`high` in the report, `info` into the number — and `info`, not `low`.

    This first shipped as `low`, following the `dynamic_attributable` rule
    beside it. `low` weighs 4 and saturates like any other severity: measured on
    the first real Linux detonation, five demoted signals took a sample from
    29.5 to 31.4 while the commit that introduced them claimed they "do not move
    the number". `info` weighs 0.0, which is what "recorded, not counted against
    the file" already means everywhere else in this engine.
    """
    assert scoring.SEVERITY_WEIGHT["info"] == 0.0
    assert scoring.SEVERITY_WEIGHT["low"] > 0
    assert scoring.effective_severity(DELETES, family="elf") == "info"
    assert scoring.effective_severity(STEALTH, family="elf") == "info"


def test_the_same_signals_still_score_on_a_calibrated_platform() -> None:
    """This is a statement about ELF, not a way to silence a signal."""
    assert scoring.effective_severity(DELETES, family="pe") == "high"
    assert scoring.effective_severity(STEALTH, family="pe") == "high"


def test_a_linux_detonation_names_no_capability_and_no_threat() -> None:
    """`detect_capabilities` is severity-blind, so demoting the score is not
    enough on its own — the same asymmetry that let the `unbacked_*` cluster
    yield `injection` while every row read `low`."""
    result = verdict.classify("elf", "application/x-elf", [_dynamic_result(DELETES, STEALTH)],
                              IOCs(), 0.0)
    assert not getattr(result, "capabilities", []) or "destruction" not in result.capabilities
    assert "DeletesFiles" not in result.threat_name, result.threat_name
    assert result.verdict == "clean", result.verdict


def test_the_evidence_itself_is_untouched() -> None:
    """Demoted for scoring, never removed. An analyst must still see exactly
    what the sandbox observed — that is the whole point of running it."""
    signals = [DELETES, STEALTH]
    result = verdict.classify("elf", "application/x-elf", [_dynamic_result(*signals)],
                              IOCs(), 0.0)
    reported = {
        row["result"] for row in getattr(result, "engines", []) or []
    }
    assert reported, "the detonation must still appear in the engine panel"
    # And the Signal objects were not mutated by scoring.
    assert DELETES.severity == "high" and STEALTH.severity == "high"


def test_static_elf_findings_still_accuse() -> None:
    """The gag is on the DYNAMIC tier only. Static ELF analysis was measured
    against 75 malware samples and 220 stock binaries and it keeps its teeth."""
    packed = Signal(id="elf.packed", title="packed", severity="high", detail="", evidence={})
    assert scoring.effective_severity(packed, family="elf") == "high"


@pytest.mark.parametrize("family", ["pe", "script", "office", "pdf", "rtf", "lnk"])
def test_no_other_platform_was_gagged(family) -> None:
    assert not scoring.dynamic_uncalibrated(family)


def test_removing_the_gag_requires_a_corpus_first() -> None:
    """A guard on the reason, not just the value.

    If someone deletes `elf` from the set, this fails and points at what has to
    exist first — a benign Linux corpus and the demotion lists built from it.
    """
    assert scoring.dynamic_uncalibrated("elf"), (
        "ELF dynamic signals are scoring again. Before enabling this, build a "
        "benign Linux corpus and populate AMBIENT_SIGNALS / "
        "FAMILY_AMBIENT_SIGNALS from what fires on software that is not "
        "malware -- capev2.deletes_files fires on any unlink, and "
        "capev2.stealth_network is a guaranteed false positive on Linux."
    )


def test_an_uncalibrated_platform_asserts_no_attack_technique() -> None:
    """A technique in the ATT&CK panel is an accusation with a reference number.

    `mitre.map_techniques` has no severity gate — a blanket one was measured and
    rejected because it removed 362 techniques including 28 on malicious
    samples — so demoting a signal for scoring does not stop it mapping. On the
    first real ELF detonation `capev2.stealth_network`, the guaranteed Linux
    false positive, asserted **Application Layer Protocol** on a report whose
    score had deliberately ignored it.
    """
    from app.engine import mitre

    everything = mitre.map_techniques([STEALTH, DELETES])
    gagged = mitre.map_techniques(
        [STEALTH, DELETES],
        exclude={s.id for s in (STEALTH, DELETES)},
    )
    assert not gagged, gagged
    # And the exclusion is doing something rather than the ids mapping to
    # nothing in the first place, which would make this test vacuous.
    assert everything, "neither signal maps to a technique; pick ids that do"


def test_a_calibrated_platform_still_maps() -> None:
    from app.engine import mitre

    assert mitre.map_techniques([STEALTH, DELETES], exclude=None)


def test_a_signal_that_arrives_low_is_also_gagged() -> None:
    """The leak that survived the first correction.

    `effective_severity` returns early for anything that is not
    medium/high/critical, so a signal CAPE itself reports at `low` never reached
    the rule — and `low` weighs 4, not 0. Measured on one sample: static-only
    29.5, with the detonation 31.4 before the first fix and still 31.1 after it,
    because `stealth_network` and `reads_files` arrive at `low`.

    An uncalibrated platform contributes nothing at whatever severity it
    arrives.
    """
    low_signal = Signal(
        id="capev2.stealth_network", title="low from CAPE",
        severity="low", detail="", evidence={},
    )
    assert scoring.effective_severity(low_signal, family="elf") == "info"
    assert scoring.effective_severity(low_signal, family="pe") == "low"

    info_signal = Signal(
        id="capev2.reads_files", title="info from CAPE",
        severity="info", detail="", evidence={},
    )
    assert scoring.effective_severity(info_signal, family="elf") == "info"


def test_the_whole_detonation_contributes_exactly_nothing() -> None:
    """The claim, asserted as arithmetic rather than as prose.

    Score the static findings alone, then score them with a full detonation
    folded in. The two numbers have to be identical.
    """
    static = [
        Signal(id="elf.packed", title="packed", severity="high", detail="", evidence={}),
        Signal(id="elf.no_sections", title="stripped", severity="medium", detail="", evidence={}),
    ]
    detonation = [
        Signal(id="capev2.stealth_network", title="", severity="low", detail="", evidence={}),
        Signal(id="capev2.reads_files", title="", severity="low", detail="", evidence={}),
        Signal(id="capev2.drops_files", title="", severity="medium", detail="", evidence={}),
        Signal(id="capev2.writes_files", title="", severity="medium", detail="", evidence={}),
        Signal(id="capev2.deletes_files", title="", severity="high", detail="", evidence={}),
    ]

    alone = scoring.assess(
        [AnalyzerResult(analyzer="elf", ran=True, signals=static)],
        ioc_total=0, family="elf",
    )
    with_trace = scoring.assess(
        [
            AnalyzerResult(analyzer="elf", ran=True, signals=static),
            _dynamic_result(*detonation),
        ],
        ioc_total=0, family="elf",
    )
    assert with_trace.rule_score == alone.rule_score, (
        "the detonation moved the rule score from %s to %s"
        % (alone.rule_score, with_trace.rule_score)
    )


# --- the third leak: the IMPACT rating, inside the signed evidence ------------
#
# The guard leaked into the score, then past `effective_severity`'s early
# return, and then here. `impact.assess` built its own exclusion set and its
# comment said it was "verdict.py's, deliberately and exactly" — which stopped
# being true the moment `verdict.classify` gained a third term.
#
# `detect_capabilities` reads `signal.severity`, not `effective_severity`, so
# forcing the signals to `info` did nothing at all here. Measured on the
# deployed image, same static findings, once alone and once with the first real
# Linux detonation folded in:
#
#     family elf   impact 0.0 / none  ->  5.3 / medium
#                  capabilities  + Network / C2 communication
#                                + Carries an executable payload
#     family pe    identical numbers, i.e. the guard had NO effect whatsoever
#
# And `report.reproducible.impact` travels inside the Ed25519-signed bundle, so
# this was a signed claim about an uncalibrated platform.

_STATIC = [
    Signal(id="elf.packed", title="packed", severity="high", detail="", evidence={}),
    Signal(id="elf.no_sections", title="no sections", severity="medium", detail="", evidence={}),
]

#: What the first real Linux detonation on cape4 actually reported.
_DETONATION = [
    Signal(id="capev2.stealth_network", title="network without a network call",
           severity="low", detail="", evidence={}),
    Signal(id="capev2.reads_files", title="reads files", severity="low", detail="", evidence={}),
    Signal(id="capev2.drops_files", title="drops files", severity="medium", detail="", evidence={}),
    Signal(id="capev2.deletes_files", title="deletes files", severity="high", detail="", evidence={}),
]


def _impact(family, signals):
    from app.engine import impact as impact_mod

    rating = impact_mod.assess(family, signals, IOCs())
    out = rating.to_dict() if hasattr(rating, "to_dict") else dict(rating)
    return out.get("base_score"), tuple(sorted(out.get("capabilities") or []))


def test_the_detonation_does_not_move_the_impact_rating() -> None:
    """Asserted as arithmetic, not prose: identical in, identical out."""
    before = _impact("elf", _STATIC)
    after = _impact("elf", _STATIC + _DETONATION)
    assert before == after, (
        "a Linux detonation moved the impact rating from %r to %r — and that "
        "rating is inside the signed evidence bundle" % (before, after)
    )


def test_a_calibrated_platform_still_has_its_impact_raised() -> None:
    """The control. This is a statement about ELF, not a way to mute a tier."""
    before = _impact("pe", _STATIC)
    after = _impact("pe", _STATIC + _DETONATION)
    assert after != before, "the guard leaked onto a calibrated platform"
    assert after[0] > before[0]


def test_one_definition_of_what_an_uncalibrated_platform_may_assert() -> None:
    """Four inline copies of this decision existed and two of them drifted.

    `verdict.classify`, `impact.assess` and both `mitre.map_techniques` callers
    must ask the same function, or the next one to gain a term leaves the others
    behind — which is exactly how the impact rating ended up signed.
    """
    import pathlib

    from app.engine import scoring

    assert scoring.uncalibrated_dynamic_ids("elf", _DETONATION) == {
        s.id for s in _DETONATION
    }
    assert scoring.uncalibrated_dynamic_ids("pe", _DETONATION) == frozenset()
    assert scoring.uncalibrated_dynamic_ids("elf", _STATIC) == frozenset()

    # Walk up rather than counting parents: this module sits at
    # backend/app/engine/ in the repository and /app/app/engine/ in the image,
    # and a fixed index is right in exactly one of those.
    here = pathlib.Path(scoring.__file__).resolve()
    root = next(
        parent for parent in here.parents
        if (parent / "app" / "engine" / "verdict.py").is_file()
    )
    for relative in ("app/engine/verdict.py", "app/engine/impact.py",
                     "app/api/dynamic.py", "app/engine/pipeline.py"):
        source = (root / relative).read_text(encoding="utf-8")
        assert 'startswith("capev2.")' not in source, (
            f"{relative} builds its own uncalibrated-platform set again; use "
            "scoring.uncalibrated_dynamic_ids so the four cannot drift"
        )
