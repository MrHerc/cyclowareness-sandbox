"""One fact, observed by four detectors, is still one fact.

Severity banding already saturates — the second signal in a band is worth 45% of
the first — but saturation assumes the signals are independent observations.
Packing indicators are not. A UPX-packed binary trips the entropy check AND the
section-size check AND the packer-name check AND a UPX YARA rule, by
construction, every time. Nothing has been learned after the first one.

Measured on Rufus — a signed, widely-used disk utility that ships UPX-packed:

    rule score 74.1, three of its six high signals being that one fact
    (43 of the 46.9 points its high band contributed)
    two engines "agreeing": CS-Static/PE and CS-YARA/upx_packed_executable
    verdict: MALICIOUS at 64, with no accusing capability at all

Both halves mattered. Collapsing the score alone took it to 45.3 and it was still
malicious, because `caps and final_score >= 30 and detected >= 2` was satisfied by
the same fact counted as two independent engines. A detection panel is only worth
reading if its rows are independent opinions.

This is not a deny-list of signals benign software trips. Which detectors are
correlated is a property of the detectors, knowable in advance, and finite.
"""
from __future__ import annotations

import pytest

from app.engine import scoring, verdict
from app.engine.contracts import IOCs, AnalyzerResult, Signal


def _sig(sid: str, severity: str = "high") -> Signal:
    return Signal(id=sid, title=sid, severity=severity, detail="", evidence={})


PACKED = [
    _sig("pe.high_entropy_section"),
    _sig("pe.section_size_anomaly"),
    _sig("yara.upx_packed_executable"),
]


def test_the_group_is_populated() -> None:
    """An empty map silently restores every behaviour this file guards."""
    assert scoring.EVIDENCE_GROUPS
    assert scoring.EVIDENCE_GROUPS["pe.high_entropy_section"] == "packed"


def test_three_ways_of_saying_packed_score_as_one() -> None:
    one, _ = scoring.rule_score([PACKED[0]])
    three, _ = scoring.rule_score(PACKED)
    assert three == one, (
        f"three packing signals scored {three} where one scores {one}; "
        "the same fact is being counted three times"
    )


def test_a_second_independent_finding_still_adds() -> None:
    """The fix must not flatten genuinely different evidence."""
    packed_only, _ = scoring.rule_score(PACKED)
    with_other, _ = scoring.rule_score([*PACKED, _sig("pe.import_combination")])
    assert with_other > packed_only


def test_the_strongest_member_is_the_one_kept() -> None:
    """Collapsing must not quietly downgrade the fact to its weakest witness."""
    mixed = [
        _sig("pe.high_entropy_section", "medium"),
        _sig("yara.upx_packed_executable", "high"),
    ]
    collapsed, detail = scoring.rule_score(mixed)
    high_band = [band for band in detail if band["severity"] == "high"]
    assert high_band, f"the high-severity member was dropped: {detail}"


# --- the panel ---------------------------------------------------------------


def _classify(signals_by_analyzer: dict[str, list[Signal]], score: float):
    results = [
        AnalyzerResult(analyzer=name, ran=True, signals=sigs, facts={}, iocs=IOCs())
        for name, sigs in signals_by_analyzer.items()
    ]
    return verdict.classify("pe", "application/x-dosexec", results, None, score)


def test_two_detectors_of_one_fact_count_as_one_detection() -> None:
    got = _classify(
        {
            "pe": [_sig("pe.high_entropy_section"), _sig("pe.section_size_anomaly")],
            "yara": [_sig("yara.upx_packed_executable")],
        },
        score=45.0,
    )
    fired = [e["engine"] for e in got.engines if e["detected"]]
    assert len(fired) >= 2, f"expected both rows to show as detections: {fired}"
    assert got.detected == 1, (
        f"'packed' was counted {got.detected} times across {fired}; "
        "one fact seen twice is not two independent findings"
    )


def test_the_panel_still_shows_every_row() -> None:
    """Collapsing the COUNT must not hide a row from the analyst."""
    got = _classify(
        {
            "pe": [_sig("pe.high_entropy_section")],
            "yara": [_sig("yara.upx_packed_executable")],
        },
        score=45.0,
    )
    shown = [e["engine"] for e in got.engines if e["detected"]]
    assert any("YARA" in name for name in shown)
    assert any("Static/PE" in name for name in shown)


def test_a_packed_binary_alone_is_not_malicious() -> None:
    """Rufus, reduced to the evidence that convicted it."""
    got = _classify(
        {
            "pe": [_sig("pe.high_entropy_section"), _sig("pe.section_size_anomaly")],
            "yara": [_sig("yara.upx_packed_executable")],
        },
        score=45.3,
    )
    assert got.verdict != "malicious", f"packed alone -> {got.verdict} ({got.to_dict()})"


def test_an_analyzer_that_found_something_else_too_is_not_collapsed() -> None:
    """A PE analyzer firing on packing AND on an import chain is a real second
    opinion, and collapsing it would hide a genuine finding."""
    got = _classify(
        {
            "pe": [_sig("pe.high_entropy_section"), _sig("pe.import_combination")],
            "yara": [_sig("yara.upx_packed_executable")],
        },
        score=45.0,
    )
    assert got.detected >= 2, (
        "the PE row rested on more than packing and should count separately"
    )


@pytest.mark.parametrize("signal_id", sorted(scoring.EVIDENCE_GROUPS))
def test_every_grouped_signal_is_about_packing(signal_id: str) -> None:
    """A guard on the guard: this map suppresses evidence, so it must not grow
    into a place where inconvenient signals are quietly filed away."""
    assert scoring.EVIDENCE_GROUPS[signal_id] == "packed"
    assert any(
        token in signal_id
        for token in ("packer", "packed", "entropy", "section", "entrypoint")
    ), f"{signal_id} is in the packing group but does not look like a packing signal"


# --- rate limiter identity ---------------------------------------------------


def test_two_keys_sharing_a_prefix_get_separate_budgets() -> None:
    """`key:{api_key[:8]}` put every credential with a common prefix in ONE
    bucket, and keys are issued with prefixes exactly like `ck_live_`. Two
    tenants would then share a 20-per-minute allowance, so either could exhaust
    the other's simply by using the product."""
    from app.ratelimit import _identity

    class _Req:
        def __init__(self, key):
            self.headers = {"x-api-key": key}
            self.client = None

    acme = _identity(_Req("ck_live_acme_0000000000"))
    globex = _identity(_Req("ck_live_globex_111111"))
    assert acme != globex, "two tenants' keys collided into one rate-limit bucket"


def test_the_rate_limit_identity_does_not_contain_the_credential() -> None:
    """It is logged and stored; a bearer credential must not be in either."""
    from app.ratelimit import _identity

    class _Req:
        def __init__(self, key):
            self.headers = {"x-api-key": key}
            self.client = None

    secret = "ck_live_supersecret_value"
    assert secret not in _identity(_Req(secret))
    assert secret[:8] not in _identity(_Req(secret))
