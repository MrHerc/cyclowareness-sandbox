"""Risk scoring: rules, a small model, and an explanation for every point.

The national sandbox hackathon brief asks for `final = 0.6 * rule_score + 0.4 * ai_score`, and that
is what this produces. What it also produces — and what actually matters — is a
breakdown an analyst can argue with. A score nobody can interrogate is a number,
not an assessment, and the first time it is wrong it costs all the trust the
right ones earned.

Two components:

**Rule score.** Severity-weighted, with saturation. Twenty low-severity
observations must not add up to one critical one, because they are not the same
evidence: a hundred suspicious strings is a style, one process-injection import
chain is an intent. Each severity band therefore contributes on a curve that
flattens, and the bands are summed rather than the individual signals.

**Model score.** A logistic regression over eight features, with weights set
from domain knowledge rather than fitted to a corpus — and labelled as such
everywhere it is displayed. This is a deliberate choice, not a shortcut: there
is no labelled malware corpus in this project, and a model presented as trained
when it is not is exactly the kind of claim this codebase refuses to make
elsewhere. `fit()` is provided so the same model can be trained the moment real
labels exist, without changing anything downstream.

Every feature's contribution to the model's logit is reported, so "why is this
79 and not 40" is always answerable.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Iterable

from .contracts import SEVERITY_ORDER, AnalyzerResult, Signal, risk_level

# --- rule component -----------------------------------------------------------

#: Points the FIRST signal in each severity band is worth. Further signals in
#: the same band add progressively less (see _saturate).
SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 55.0,
    "high": 26.0,
    "medium": 11.0,
    "low": 4.0,
    "info": 0.0,
}

#: How fast a band saturates. n signals in a band contribute
#: weight * (1 - decay**n) / (1 - decay), i.e. a geometric series: the second
#: signal is worth `decay` of the first, the third `decay**2`, and so on.
_DECAY = 0.45


def _saturate(weight: float, count: int) -> float:
    if count <= 0 or weight <= 0:
        return 0.0
    return weight * (1 - _DECAY**count) / (1 - _DECAY)


#: Signals that are all evidence of the SAME underlying fact, grouped so the fact
#: is scored once instead of once per detector that noticed it.
#:
#: Banding already saturates — the second signal in a band is worth 45% of the
#: first — but saturation assumes the signals are independent observations. These
#: are not. "This binary is packed" is one fact, and a packed binary trips the
#: entropy check AND the section-size check AND the packer-name check AND a UPX
#: YARA rule, by construction, every time.
#:
#: Measured: Rufus, a signed and widely-used disk utility that ships UPX-packed,
#: scored 74.1 on the rule side with three of its six high signals being that one
#: fact — 43 of the 46.9 points its high band contributed — and came out
#: `malicious` at 64 with no accusing capability at all.
#:
#: This is not a deny-list of "signals benign software trips". It is a statement
#: about which detectors are correlated by construction, which is a property of
#: the detectors and knowable in advance.
EVIDENCE_GROUPS: dict[str, str] = {
    # Is this binary packed? Four ways of asking one question.
    "pe.high_entropy_section": "packed",
    "pe.section_size_anomaly": "packed",
    "pe.packer_section_name": "packed",
    "yara.upx_packed_executable": "packed",
    "capev2.packer_entropy": "packed",
    "capev2.packer_unknown_pe_section_name": "packed",
    "capev2.pe_section_vsize_rsize_anomaly": "packed",
    "capev2.pe_deep_entrypoint": "packed",
}


def _collapse_correlated(signals: list[Signal]) -> list[Signal]:
    """Keep the strongest signal from each correlated group, drop the rest.

    The strongest is kept rather than the group being dropped: the fact is real
    and should score. It should just score once.
    """
    strongest: dict[str, Signal] = {}
    out: list[Signal] = []
    for signal in signals:
        group = EVIDENCE_GROUPS.get(signal.id)
        if group is None:
            out.append(signal)
            continue
        current = strongest.get(group)
        if current is None or SEVERITY_ORDER.get(signal.severity, 0) > SEVERITY_ORDER.get(
            current.severity, 0
        ):
            strongest[group] = signal
    out.extend(strongest.values())
    return out


def rule_score(signals: Iterable[Signal]) -> tuple[float, list[dict[str, Any]]]:
    """Severity-weighted rule score in 0-100, plus the per-band arithmetic."""
    bands: dict[str, list[Signal]] = {}
    for signal in _collapse_correlated(list(signals)):
        bands.setdefault(signal.severity, []).append(signal)

    total = 0.0
    detail: list[dict[str, Any]] = []
    for severity in ("critical", "high", "medium", "low"):
        matched = bands.get(severity, [])
        if not matched:
            continue
        contribution = _saturate(SEVERITY_WEIGHT[severity], len(matched))
        total += contribution
        detail.append(
            {
                "severity": severity,
                "count": len(matched),
                "contribution": round(contribution, 1),
                "signals": [s.id for s in matched],
            }
        )

    return min(100.0, round(total, 1)), detail


# --- model component ----------------------------------------------------------


@dataclass
class Features:
    """The eight inputs to the model, each bounded to roughly 0-1.

    Bounded on purpose: an unbounded feature lets one pathological sample
    dominate the logit, and the resulting score is unexplainable precisely when
    it matters most.
    """

    yara_hits: float = 0.0
    max_entropy: float = 0.0
    capability_signals: float = 0.0
    ioc_density: float = 0.0
    extension_mismatch: float = 0.0
    obfuscation_layers: float = 0.0
    autoexec: float = 0.0
    embedded_executable: float = 0.0

    NAMES = (
        "yara_hits",
        "max_entropy",
        "capability_signals",
        "ioc_density",
        "extension_mismatch",
        "obfuscation_layers",
        "autoexec",
        "embedded_executable",
    )

    def as_dict(self) -> dict[str, float]:
        return {n: round(getattr(self, n), 3) for n in self.NAMES}


#: Expert-set coefficients. Positive raises the probability of "malicious".
#: The ordering encodes a judgement worth stating plainly: intent beats
#: appearance. A macro that runs on open, or content that contradicts its own
#: filename, is a decision someone made; high entropy is a property a legitimate
#: installer also has.
WEIGHTS: dict[str, float] = {
    "yara_hits": 2.6,
    "max_entropy": 1.5,
    "capability_signals": 2.9,
    "ioc_density": 0.9,
    "extension_mismatch": 2.2,
    "obfuscation_layers": 2.4,
    "autoexec": 2.1,
    "embedded_executable": 1.8,
}
#: Chosen so an all-zero feature vector scores ~5, not 50. A file we found
#: nothing in should read as "nothing found", not as a coin flip.
BIAS: float = -3.1

MODEL_PROVENANCE = (
    "Expert-weighted logistic model (8 features). Coefficients are set from "
    "domain knowledge, not fitted to a labelled corpus — the contribution of "
    "every feature is shown so the score can be checked by hand."
)

#: Feature ids whose presence means "this binary can do something", used to
#: build `capability_signals`.
_CAPABILITY_PREFIXES = (
    "pe.import_combination",
    "script.download_and_execute",
    "script.dynamic_execution",
    "script.credential_access",
    "script.persistence",
    "script.defense_evasion",
    "script.amsi_or_etw_tamper",
    "office.macro_suspicious_call",
    "office.remote_template",
    "office.dde_field",
    "pdf.launch_action",
    "pdf.submit_form",
    "elf.suspicious_strings",
    "apk.dangerous_permission",
    "apk.suspicious_api",
    "apk.accessibility_abuse",
    "jar.runtime_exec",
    "jar.reflection",
    "jar.classloader",
    "jar.script_engine",
    "diskimage.embedded_executable",
    "diskimage.autorun",
    "intel.vt_malicious",
)


def extract_features(results: Iterable[AnalyzerResult], signals: list[Signal], ioc_total: int) -> Features:
    results = list(results)
    ids = [s.id for s in signals]

    yara = sum(1 for i in ids if i.startswith("yara."))

    entropy = 0.0
    for result in results:
        facts = result.facts or {}
        for key in ("max_section_entropy", "entropy", "overall_entropy"):
            value = facts.get(key)
            if isinstance(value, (int, float)):
                entropy = max(entropy, float(value))
        for section in facts.get("sections", []) or []:
            if isinstance(section, dict) and isinstance(section.get("entropy"), (int, float)):
                entropy = max(entropy, float(section["entropy"]))

    capabilities = sum(1 for i in ids if any(i.startswith(p) for p in _CAPABILITY_PREFIXES))
    layers = sum(1 for i in ids if i == "script.decoded_layer")

    return Features(
        # Diminishing returns: five YARA hits is not five times one.
        yara_hits=min(1.0, yara / 4.0),
        # Below 6.0 is ordinary content; 8.0 is the theoretical maximum.
        max_entropy=max(0.0, min(1.0, (entropy - 6.0) / 2.0)),
        capability_signals=min(1.0, capabilities / 3.0),
        ioc_density=min(1.0, ioc_total / 25.0),
        extension_mismatch=1.0 if "generic.extension_mismatch" in ids else 0.0,
        obfuscation_layers=min(1.0, layers / 2.0),
        autoexec=1.0 if "office.autoexec_macro" in ids else 0.0,
        embedded_executable=1.0 if "generic.embedded_executable" in ids else 0.0,
    )


def model_score(features: Features) -> tuple[float, list[dict[str, Any]]]:
    """Probability of malicious, as 0-100, with each feature's contribution."""
    contributions: list[dict[str, Any]] = []
    logit = BIAS
    for name in Features.NAMES:
        value = getattr(features, name)
        weight = WEIGHTS[name]
        contribution = value * weight
        logit += contribution
        if value:
            contributions.append(
                {
                    "feature": name,
                    "value": round(value, 3),
                    "weight": weight,
                    "contribution": round(contribution, 3),
                }
            )

    contributions.sort(key=lambda c: -c["contribution"])
    probability = 1.0 / (1.0 + math.exp(-logit))
    return round(probability * 100, 1), contributions


def fit(samples: list[tuple[Features, int]], *, epochs: int = 400, lr: float = 0.15) -> dict[str, float]:
    """Train the same model on real labels, when there are any.

    Present so the expert weights are a starting point rather than a ceiling:
    the moment Cyclowareness Sandbox has a labelled corpus, this replaces WEIGHTS and nothing
    downstream changes. Plain gradient descent — eight features do not justify
    a dependency.
    """
    weights = dict(WEIGHTS)
    bias = BIAS
    for _ in range(epochs):
        for features, label in samples:
            logit = bias + sum(getattr(features, n) * weights[n] for n in Features.NAMES)
            error = (1.0 / (1.0 + math.exp(-logit))) - label
            for name in Features.NAMES:
                weights[name] -= lr * error * getattr(features, name)
            bias -= lr * error
    return {**weights, "__bias__": bias}


# --- aggregation ---------------------------------------------------------------

RULE_WEIGHT = 0.6
MODEL_WEIGHT = 0.4

#: The split is runtime-tunable (the brief asks for weights exposed in the admin
#: UI for hackathon tuning). In-memory: an override lasts for the process, and a
#: restart returns to the 0.6/0.4 default. Only the ratio matters, so any two
#: positive numbers are normalised to sum to 1.
_active = {"rule": RULE_WEIGHT, "model": MODEL_WEIGHT}


def get_weights() -> dict[str, float]:
    return dict(_active)


def set_weights(rule_weight: float, model_weight: float) -> dict[str, float]:
    total = rule_weight + model_weight
    if total <= 0 or rule_weight < 0 or model_weight < 0:
        raise ValueError("weights must be non-negative and sum to a positive number")
    _active["rule"] = round(rule_weight / total, 4)
    _active["model"] = round(model_weight / total, 4)
    return get_weights()


def reset_weights() -> dict[str, float]:
    _active["rule"] = RULE_WEIGHT
    _active["model"] = MODEL_WEIGHT
    return get_weights()


@dataclass
class Assessment:
    rule_score: float
    ai_score: float
    final_score: float
    risk_level: str
    breakdown: dict[str, Any] = field(default_factory=dict)


def assess(
    results: Iterable[AnalyzerResult],
    *,
    ioc_total: int,
    tiers: dict[str, Any] | None = None,
) -> Assessment:
    results = list(results)
    signals = [s for r in results if r.ran for s in r.signals]

    rules, rule_detail = rule_score(signals)
    features = extract_features(results, signals, ioc_total)
    ai, contributions = model_score(features)
    weights = get_weights()
    final = round(weights["rule"] * rules + weights["model"] * ai, 1)

    #: The top three reasons, in the words the analyzers used. This is what the
    #: PDF's executive summary and the UI headline both read from, so there is
    #: exactly one answer to "why".
    ranked = sorted(signals, key=lambda s: -SEVERITY_ORDER.get(s.severity, 0))
    top = [
        {"id": s.id, "title": s.title, "severity": s.severity, "detail": s.detail[:300]}
        for s in ranked[:3]
    ]

    return Assessment(
        rule_score=rules,
        ai_score=ai,
        final_score=final,
        risk_level=risk_level(final),
        breakdown={
            "formula": f"final = {weights['rule']} x rule + {weights['model']} x model",
            "rule": {"score": rules, "bands": rule_detail, "signal_count": len(signals)},
            "model": {
                "score": ai,
                "provenance": MODEL_PROVENANCE,
                "features": features.as_dict(),
                "contributions": contributions,
                "bias": BIAS,
            },
            "top_reasons": top,
            # Which tiers actually ran. A score computed without dynamic
            # analysis is a score with a stated blind spot, and saying so is the
            # difference between a verdict and a guess.
            "tiers": tiers or {},
        },
    )
