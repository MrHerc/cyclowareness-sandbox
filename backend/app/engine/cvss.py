"""CVSS v3.1 severity for an analysed sample.

Two honest halves:

1. **The maths is the real CVSS v3.1 specification** — the exact metric value
   tables, the scope-dependent impact and exploitability equations, and the
   official `roundup`. Given a vector, ``score()`` returns exactly what the
   FIRST.org calculator returns. This is verified against the specification's
   worked examples in the test suite.

2. **The metric selection is derived from what static analysis observed**, and
   the reason for every metric is reported. CVSS was designed for
   vulnerabilities, so applying it to a malware sample is a modelling choice:
   we read the sample's capabilities (does it reach the network, steal
   credentials, persist, evade defences, destroy data) and map them onto the
   base metrics. The number is real CVSS; the inputs are a transparent,
   arguable mapping — which is exactly how it is labelled everywhere it shows.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Iterable

from .capabilities import detect as detect_capabilities
from .contracts import IOCs, Signal

# --- CVSS v3.1 metric value tables (from the specification) -------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # scope changed
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

_METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _roundup(value: float) -> float:
    """The official CVSS v3.1 roundup: ceil to one decimal, float-safe."""
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
    """Compute the CVSS v3.1 base score from a metrics dict (letters)."""
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
    return "CVSS:3.1/" + "/".join(f"{m}:{metrics[m]}" for m in _METRIC_ORDER)


# --- capability model: observed behaviour -> base metrics ---------------------


@dataclass
class CvssResult:
    vector: str
    base_score: float
    severity: str
    metrics: dict[str, str]
    rationale: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vector": self.vector,
            "base_score": self.base_score,
            "severity": self.severity,
            "metrics": self.metrics,
            "rationale": self.rationale,
        }


def _has(caps: set[str], *names: str) -> bool:
    return any(n in caps for n in names)


def assess(
    family: str,
    signals: Iterable[Signal],
    iocs: IOCs | None = None,
    *,
    from_url: bool = False,
) -> CvssResult:
    """Derive a CVSS v3.1 vector from a sample's family, signals and IOCs."""
    signals = list(signals)
    caps = detect_capabilities(signals, iocs)
    has_exec_capable = bool(signals) and family in {"pe", "elf", "script", "apk", "jar", "office", "pdf"}
    rationale: list[dict[str, str]] = []

    def note(metric: str, value: str, why: str) -> str:
        rationale.append({"metric": metric, "value": value, "why": why})
        return value

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

    # Scope: persistence / privilege / defence evasion affect components beyond the sample.
    if _has(caps, "persistence", "privilege", "evasion"):
        s = note("S", "C", "Affects the wider system (persistence / privilege / defence tampering)")
    else:
        s = note("S", "U", "Impact contained to the executing context")

    # Confidentiality: credential/data/PII access.
    if _has(caps, "credential"):
        c = note("C", "H", "Accesses credentials / device data / messages")
    elif has_exec_capable:
        c = note("C", "L", "Executes code that can read local data")
    else:
        c = note("C", "N", "No confidentiality impact observed")

    # Integrity: code execution, dropping/modifying files, persistence, injection.
    if _has(caps, "network", "injection", "persistence", "exploit") or has_exec_capable:
        i = note("I", "H", "Executes / drops code, injects, or persists")
    else:
        i = note("I", "N", "No integrity impact observed")

    # Availability: destructive / ransomware behaviour.
    if _has(caps, "destruction"):
        a = note("A", "H", "Destructive / ransomware behaviour")
    elif _has(caps, "persistence") and _has(caps, "network"):
        a = note("A", "L", "Resource use from persistent network activity")
    else:
        a = note("A", "N", "No availability impact observed")

    metrics = {"AV": av, "AC": ac, "PR": pr, "UI": ui, "S": s, "C": c, "I": i, "A": a}
    base = score(metrics)
    return CvssResult(
        vector=vector_string(metrics),
        base_score=base,
        severity=severity_of(base),
        metrics=metrics,
        rationale=rationale,
    )
