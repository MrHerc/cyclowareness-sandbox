"""Scoring: rule saturation, model contributions, and weight tuning.

The two components are checked for the properties the design promises — that a
crowd of weak signals cannot out-vote one strong one, and that every point the
model contributes is attributable to a named feature.
"""
from __future__ import annotations

import pytest

from app.engine import scoring
from app.engine.contracts import AnalyzerResult, IOCs, Signal


def _lows(n: int) -> list[Signal]:
    return [Signal(id=f"low.{i}", title="minor", severity="low") for i in range(n)]


def test_rule_score_saturates_so_many_lows_beat_by_one_critical():
    twenty_low, _ = scoring.rule_score(_lows(20))
    one_critical, _ = scoring.rule_score([Signal(id="c", title="bad", severity="critical")])

    # Twenty low observations must not add up to a single critical one.
    assert twenty_low < one_critical
    # And the saturating band never runs away: the low band's geometric series
    # converges to weight/(1-decay) ~= 7.27, so 20 lows stay well under 8.
    assert twenty_low < 8.0


def test_rule_score_is_bounded_to_100():
    crowd = [
        Signal(id=f"c.{i}", title="bad", severity="critical") for i in range(50)
    ]
    total, _ = scoring.rule_score(crowd)
    assert total <= 100.0


def test_model_contributions_are_present_and_named():
    # Signals that light up several model features: a YARA hit, a capability, an
    # obfuscation layer, plus extracted IOCs.
    signals = [
        Signal(id="yara.some_rule", title="yara", severity="high"),
        Signal(id="script.download_and_execute", title="dl", severity="high"),
        Signal(id="script.decoded_layer", title="layer", severity="medium"),
        Signal(id="generic.extension_mismatch", title="mismatch", severity="high"),
    ]
    result = AnalyzerResult(analyzer="script", ran=True, signals=signals)

    assessment = scoring.assess([result], ioc_total=12)
    model = assessment.breakdown["model"]

    assert model["contributions"], "expected at least one feature to contribute"
    contributed = {c["feature"] for c in model["contributions"]}
    # The features those signals were designed to move.
    assert "yara_hits" in contributed
    assert "capability_signals" in contributed
    assert "extension_mismatch" in contributed
    # Provenance is stated, and it is the expert-weighted (not corpus-trained) model.
    assert "expert" in model["provenance"].lower()
    assert 0.0 <= assessment.ai_score <= 100.0


def test_final_score_uses_the_documented_formula_and_bands():
    signals = [Signal(id="c", title="bad", severity="critical")]
    result = AnalyzerResult(analyzer="x", ran=True, signals=signals)
    assessment = scoring.assess([result], ioc_total=0)

    weights = scoring.get_weights()
    expected = round(
        weights["rule"] * assessment.rule_score + weights["model"] * assessment.ai_score, 1
    )
    assert assessment.final_score == expected
    assert assessment.risk_level in ("low", "medium", "high", "critical")


def test_set_weights_normalises_to_sum_one():
    weights = scoring.set_weights(3.0, 1.0)
    assert weights["rule"] == pytest.approx(0.75)
    assert weights["model"] == pytest.approx(0.25)
    assert weights["rule"] + weights["model"] == pytest.approx(1.0)


def test_set_weights_rejects_invalid_inputs():
    with pytest.raises(ValueError):
        scoring.set_weights(0.0, 0.0)
    with pytest.raises(ValueError):
        scoring.set_weights(-1.0, 2.0)


def test_reset_weights_restores_the_default_split():
    scoring.set_weights(9.0, 1.0)
    restored = scoring.reset_weights()
    assert restored["rule"] == pytest.approx(scoring.RULE_WEIGHT)
    assert restored["model"] == pytest.approx(scoring.MODEL_WEIGHT)


def test_weight_change_moves_the_final_score():
    signals = [Signal(id="c", title="bad", severity="critical")]
    result = AnalyzerResult(analyzer="x", ran=True, signals=signals, iocs=IOCs())

    scoring.set_weights(1.0, 0.0)  # rule only
    rule_only = scoring.assess([result], ioc_total=0)
    scoring.set_weights(0.0, 1.0)  # model only
    model_only = scoring.assess([result], ioc_total=0)

    assert rule_only.final_score == pytest.approx(rule_only.rule_score)
    assert model_only.final_score == pytest.approx(model_only.ai_score)
    assert rule_only.final_score != model_only.final_score
