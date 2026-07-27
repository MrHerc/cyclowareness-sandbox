"""Threat-intelligence enrichment: VirusTotal hash reputation.

Universal analyzer (runs on every sample), but only does anything when
``VT_API_KEY`` is configured — otherwise it reports itself unavailable and costs
nothing. A hash lookup executes no code; it asks a third party whether these
exact bytes are already known-bad, and maps the answer into the same Signal
vocabulary every other analyzer speaks. "Unknown to VirusTotal" is reported as
info, never as clean.

A hash is still data about the customer's file, so this analyzer clears the
sovereignty choke point before the key is even read. The refusal is reported as
the analyzer's unavailable reason rather than swallowed: an operator reading a
report must be able to tell "we asked and nobody knew it" apart from "we were
not permitted to ask".
"""
from __future__ import annotations

import os

from ... import sovereignty
from ..contracts import AnalyzerResult, Sample

NAME = "virustotal"
FAMILY = "*"


def analyze(sample: Sample) -> AnalyzerResult:
    key = os.environ.get("VT_API_KEY", "").strip()
    if not key:
        return AnalyzerResult.unavailable(
            "virustotal", "VT_API_KEY not set — hash reputation not checked"
        )

    # After the key check, deliberately. The refusal tally is the operator's
    # proof of what sovereign mode actually stopped, so it must count calls this
    # deployment would otherwise have made. Checking first logged a refusal for
    # every sample on every deployment that never configured VirusTotal, which
    # would have turned the number an auditor is shown into noise.
    try:
        sovereignty.check("virustotal", detail=f"sha256 {sample.sha256[:16]}")
    except sovereignty.OutboundRefused as refusal:
        return AnalyzerResult.unavailable("virustotal", refusal.reason)

    try:
        from ..integrations.virustotal import as_analyzer_result

        return as_analyzer_result(sample.sha256, key)
    except Exception as exc:  # noqa: BLE001 — enrichment must never fail the job
        return AnalyzerResult.unavailable("virustotal", f"lookup raised {type(exc).__name__}")
