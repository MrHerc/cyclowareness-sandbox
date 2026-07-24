"""Threat-intelligence enrichment: VirusTotal hash reputation.

Universal analyzer (runs on every sample), but only does anything when
``VT_API_KEY`` is configured — otherwise it reports itself unavailable and costs
nothing. A hash lookup executes no code; it asks a third party whether these
exact bytes are already known-bad, and maps the answer into the same Signal
vocabulary every other analyzer speaks. "Unknown to VirusTotal" is reported as
info, never as clean.
"""
from __future__ import annotations

import os

from ..contracts import AnalyzerResult, Sample

NAME = "virustotal"
FAMILY = "*"


def analyze(sample: Sample) -> AnalyzerResult:
    key = os.environ.get("VT_API_KEY", "").strip()
    if not key:
        return AnalyzerResult.unavailable(
            "virustotal", "VT_API_KEY not set — hash reputation not checked"
        )
    try:
        from ..integrations.virustotal import as_analyzer_result

        return as_analyzer_result(sample.sha256, key)
    except Exception as exc:  # noqa: BLE001 — enrichment must never fail the job
        return AnalyzerResult.unavailable("virustotal", f"lookup raised {type(exc).__name__}")
