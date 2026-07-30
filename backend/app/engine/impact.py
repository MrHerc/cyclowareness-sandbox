"""Cyclowareness Impact Rating (CIR v1) — how much damage this sample can do.

This used to be published as "CVSS v3.1" and it no longer is. FIRST scopes CVSS
to *vulnerabilities* — "the principal technical characteristics of software,
hardware and firmware vulnerabilities". A malware sample is not a vulnerability,
so scoring one with CVSS is a category error, and our arithmetic being exactly
right made it a precisely wrong answer rather than an approximately right one.
CVSS v4.0 has also been GA since November 2023, so shipping a v3.1 badge in 2026
invites a question with no good answer. The rating kept the maths and dropped the
borrowed name.

Two honest halves:

1. **The arithmetic is deliberately CVSS-compatible.** The metric value tables,
   the scope-dependent impact and exploitability equations and the ``roundup``
   are the CVSS v3.1 ones, so a reader who knows what an 8.8 feels like reads a
   CIR 8.8 correctly, and the number is reproducible by anyone holding the
   published equations. The specification's worked vectors are asserted in the
   test suite. What changed is the *label*, not the number.

2. **The metric selection is derived from what analysis observed**, and the
   reason for every metric is reported. We read the sample's capabilities (does
   it reach the network, steal credentials, persist, evade defences, destroy
   data) and map them onto the base metrics. The mapping is published in full in
   docs/impact-rating.md so a buyer can audit the rating rather than trust it.

The metric axes are kept because they are the right axes and they are familiar:
reachability, reliability, privilege required, interaction, blast radius, and the
confidentiality/integrity/availability triad. Only the name is ours.

**Where real CVSS belongs.** Nothing here forecloses it. If a future analyzer
identifies an actual CVE — an exploit for a known vulnerability, a vulnerable
bundled component — that finding carries a genuine CVSS vector from the CVE
record, published as its own field beside this rating. CIR rates what the sample
can do; CVSS rates a vulnerability it exploits. Those are different statements
and must never be collapsed into one number.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Iterable

from .capabilities import detect as detect_capabilities
from .contracts import IOCs, Signal

#: The rating's own notation. Deliberately not ``CVSS:3.1/``: a vector carrying
#: the CVSS prefix is a claim to *be* CVSS, and a tool that parses it as such
#: would be entitled to file the sample as a scored vulnerability.
NOTATION = "CIR:1.0"

#: The one sentence every surface (UI, PDF, JSON, STIX, docs) repeats, so the
#: rating cannot be mistaken for a vulnerability score anywhere it is read. It
#: lives here rather than being written out per surface because a disclaimer that
#: drifts between the screen and the exported case file is worse than none.
DISCLAIMER = (
    "The Cyclowareness Impact Rating (CIR v1) is derived from the capabilities this "
    "sample was observed to have. It is not a vulnerability score and it is not "
    "CVSS; it uses CVSS-compatible arithmetic so that the 0-10 scale reads the way "
    "an analyst already expects."
)

# --- metric value tables (CVSS v3.1-compatible; see the module docstring) -----
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # scope changed
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

_METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _roundup(value: float) -> float:
    """Round up to one decimal, float-safe — the CVSS v3.1 ``roundup``."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def severity_of(score: float) -> str:
    if score == 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def score(metrics: dict[str, str]) -> float:
    """Compute the CIR base score from a metrics dict (letters)."""
    av = _AV[metrics["AV"]]
    ac = _AC[metrics["AC"]]
    ui = _UI[metrics["UI"]]
    scope_changed = metrics["S"] == "C"
    pr = (_PR_C if scope_changed else _PR_U)[metrics["PR"]]
    c, i, a = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def vector_string(metrics: dict[str, str]) -> str:
    return f"{NOTATION}/" + "/".join(f"{m}:{metrics[m]}" for m in _METRIC_ORDER)


# --- capability model: observed behaviour -> base metrics ---------------------


@dataclass
class ImpactRating:
    vector: str
    base_score: float
    severity: str
    metrics: dict[str, str]
    rationale: list[dict[str, str]] = field(default_factory=list)
    #: What the evidence showed the sample can do, in the shared vocabulary.
    #: Computed here to derive the vector, and now carried out with it: an
    #: analyst's first question is "what does it do", and the answer existed but
    #: never left this function. Labels rather than internal keys, because this
    #: is read by people and by exports, not by our own code.
    capabilities: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rating": NOTATION,
            "vector": self.vector,
            "base_score": self.base_score,
            "severity": self.severity,
            "metrics": self.metrics,
            "capabilities": self.capabilities,
            "rationale": self.rationale,
            # Stored on the row, not only rendered: an exported payload has to
            # state what it is when it is read years later by something that
            # never saw our UI.
            "disclaimer": DISCLAIMER,
        }


def _capability_labels(caps: set[str]) -> list[str]:
    """Capability keys as the phrases a report shows, sorted for stable output."""
    from .capabilities import CAPABILITY_LABELS

    return sorted(CAPABILITY_LABELS.get(c, c) for c in caps)


def _has(caps: set[str], *names: str) -> bool:
    return any(n in caps for n in names)


#: The metrics of a rating that rates nothing. Every value is the benign one, so
#: the vector is still a well-formed vector a reader can parse.
_EMPTY_METRICS = {
    "AV": "L", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "N", "A": "N",
}


def unrated(why: str = "") -> ImpactRating:
    """0.0 / "none" — there is nothing here to rate, and why.

    Two callers, and the second is the point. `assess` returns this when the
    evidence demonstrates no capability. The SCORING PATHS return it when the
    engine's verdict is `clean`, because `classify` has a gate this function does
    not: it decides `clean` from the score and the detection panel, not from
    capabilities alone.

    Without that, a file whose only signals were low-severity ambient ones still
    derived five capabilities here, and the report read `Script.Clean` beside
    "Impact: 6.9 high" — 25 of 478 top-level jobs on the live deployment,
    including a `ca-bundle.crt` and a `styles.css`. A reader cannot tell which
    half to believe, and the honest answer is the half that found nothing.
    """
    return ImpactRating(
        vector=vector_string(_EMPTY_METRICS),
        base_score=0.0,
        severity="none",
        metrics=dict(_EMPTY_METRICS),
        rationale=[{
            "metric": "-",
            "value": "none",
            "why": why or (
                "No capability was demonstrated by the evidence, so there is no "
                "impact to rate."
            ),
        }],
    )


def assess(
    family: str,
    signals: Iterable[Signal],
    iocs: IOCs | None = None,
    *,
    from_url: bool = False,
) -> ImpactRating:
    """Derive a CIR vector from a sample's family, signals and IOCs.

    The rating describes an *impact*. When the evidence demonstrates no
    capability there is no impact to rate, so this returns 0.0 / none rather than
    manufacturing a vector — an earlier version granted Integrity:High to any
    file that produced even one informational signal, which rated ordinary
    documents at 7.x.
    """
    signals = list(signals)
    # THE SAME CAPABILITY SET THE VERDICT USED, OR THE TWO DISAGREE ON SCREEN.
    #
    # This called `detect_capabilities` on the raw signals while `verdict.classify`
    # dropped the demoted ones first, so a file the verdict cleared still carried
    # a rated impact: `Win32.Clean` beside "Impact: 5.4 medium", from the very
    # signals the engine had already decided do not support an accusation. A
    # reader cannot tell which half to believe, and the honest answer is that the
    # accusing half was wrong.
    #
    # The exclusions are verdict.py's, deliberately and exactly: `uncorroborated`
    # (a lone high-consequence signal is a lead, not a finding) and
    # `family_ambient` (the interpreter is not the sample). `AMBIENT_SIGNALS` is
    # NOT among them there and is not here — it is demoted for scoring only, and
    # routing it into the capability engine was measured at a cost of 16 fixture
    # detections.
    from .scoring import family_ambient, uncorroborated

    excluded = uncorroborated(signals) | family_ambient(family)
    caps = detect_capabilities(
        [s for s in signals if s.id not in excluded] if excluded else signals,
        iocs,
    )
    rationale: list[dict[str, str]] = []

    def note(metric: str, value: str, why: str) -> str:
        rationale.append({"metric": metric, "value": value, "why": why})
        return value

    if not caps:
        return unrated()

    # "Can cause code to run" — asserted only by execution/injection evidence,
    # never merely by the file being of an executable type.
    has_exec_capable = _has(caps, "execution", "injection")

    # Attack Vector: network-reachable threat if it fetches/beacons or arrived as a URL.
    av = note("AV", "N", "Reaches the network (download/C2) or was delivered by URL") if (
        _has(caps, "network") or from_url
    ) else note("AV", "L", "Requires the file to be run locally")

    # Attack Complexity: heavy obfuscation/evasion raises the bar to reliable execution.
    ac = note("AC", "H", "Obfuscated / evasive — reliable execution is conditional") if _has(caps, "evasion") \
        else note("AC", "L", "No special conditions to run")

    # Privileges Required: malware runs as whoever executes it.
    pr = note("PR", "N", "Runs with the executing user's privileges; none required beforehand")

    # User Interaction: the user opens/runs the sample (macro, script, app).
    ui = note("UI", "R", "The user must open or run the sample")

    # Scope: only things that genuinely act on components beyond the running
    # sample. Obfuscation alone does not — plenty of legitimate software is
    # packed, and treating that as a scope change inflated every installer.
    if _has(caps, "persistence", "privilege"):
        s = note("S", "C", "Acts beyond the executing process (persistence / elevation abuse)")
    else:
        s = note("S", "U", "Impact contained to the executing context")

    # Confidentiality: credential/data/PII access.
    if _has(caps, "credential"):
        c = note("C", "H", "Accesses credentials / device data / messages")
    elif has_exec_capable:
        c = note("C", "L", "Runs code that could read local data")
    else:
        c = note("C", "N", "No confidentiality impact demonstrated")

    # Integrity: running code, loading hidden code, dropping a payload, or
    # persisting. Reaching the network on its own is not an integrity impact.
    if has_exec_capable or _has(caps, "persistence", "dropper", "exploit"):
        i = note("I", "H", "Runs or loads code, drops a payload, or persists")
    elif _has(caps, "deception"):
        i = note("I", "L", "Misrepresents what it is, but no code execution was demonstrated")
    else:
        i = note("I", "N", "No integrity impact demonstrated")

    # Availability: destructive / ransomware behaviour.
    if _has(caps, "destruction"):
        a = note("A", "H", "Destructive / ransomware behaviour")
    elif _has(caps, "persistence") and _has(caps, "network"):
        a = note("A", "L", "Resource use from persistent network activity")
    else:
        a = note("A", "N", "No availability impact observed")

    metrics = {"AV": av, "AC": ac, "PR": pr, "UI": ui, "S": s, "C": c, "I": i, "A": a}
    base = score(metrics)
    return ImpactRating(
        vector=vector_string(metrics),
        base_score=base,
        severity=severity_of(base),
        metrics=metrics,
        rationale=rationale,
        capabilities=_capability_labels(caps),
    )
