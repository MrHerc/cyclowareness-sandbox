"""VirusTotal v3 hash-reputation client.

This is a *reputation* lookup, not a scan: it asks VirusTotal what its multi-
engine consensus is for a SHA-256 we already computed locally. It uploads
nothing and detonates nothing, which keeps it firmly on the static tier and
respectful of the sample owner's confidentiality — a hash reveals far less than
a file.

The one rule that governs the verdict mapping: **unknown is not clean.** A hash
VirusTotal has never seen tells us the sample is *unproven*, not *safe*. Mapping
that to a benign signal would let a novel dropper launder itself into a clean
report simply by being new. So an unknown hash produces an ``info`` signal that
says exactly that, and a seen-but-flagged hash escalates with the count.

Nothing in here raises to the caller. A dead network, a bad key, a rate-limit —
all degrade to ``{"found": False, "error": ...}`` or an ``unavailable``
AnalyzerResult, because a threat-intel outage must never take down analysis.
"""
from __future__ import annotations

import httpx

from ... import sovereignty
from ..contracts import AnalyzerResult, IOCs, Signal

_API_BASE = "https://www.virustotal.com/api/v3/files/"
_PERMALINK = "https://www.virustotal.com/gui/file/"

ANALYZER_NAME = "virustotal"


def lookup(sha256: str, api_key: str, timeout: float = 10.0) -> dict:
    """Fetch VirusTotal's verdict for one SHA-256.

    Returns a compact dict on success::

        {found: True, malicious, suspicious, harmless, undetected,
         reputation, permalink}

    or ``{found: False}`` when the hash is unknown (HTTP 404), or
    ``{found: False, error: <reason>}`` for any failure — auth, timeout,
    transport, or a malformed response. Never raises.
    """
    sha = (sha256 or "").strip().lower()
    if not sha:
        return {"found": False, "error": "empty sha256"}
    if not api_key:
        return {"found": False, "error": "no api key"}

    # Checked here as well as in the intel analyzer, because this function is
    # importable and a future caller that reaches it directly must not be able
    # to route around the choke point.
    try:
        sovereignty.check("virustotal", detail=f"sha256 {sha[:16]}")
    except sovereignty.OutboundRefused as refusal:
        return {"found": False, "error": "sovereign_mode_refused", "refusal": refusal.reason}

    headers = {"x-apikey": api_key, "accept": "application/json"}
    try:
        resp = httpx.get(_API_BASE + sha, headers=headers, timeout=timeout)
    except httpx.TimeoutException:
        return {"found": False, "error": "timeout"}
    except httpx.HTTPError as exc:
        return {"found": False, "error": f"transport: {type(exc).__name__}"}

    if resp.status_code == 404:
        # VirusTotal has never seen this hash — unknown, not clean.
        return {"found": False}
    if resp.status_code in (401, 403):
        return {"found": False, "error": "auth"}
    if resp.status_code == 429:
        return {"found": False, "error": "rate_limited"}
    if resp.status_code != 200:
        return {"found": False, "error": f"http_{resp.status_code}"}

    try:
        attrs = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
    except (ValueError, KeyError, TypeError):
        return {"found": False, "error": "malformed_response"}

    return {
        "found": True,
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "harmless": int(stats.get("harmless", 0)),
        "undetected": int(stats.get("undetected", 0)),
        "reputation": int(attrs.get("reputation", 0)),
        "permalink": _PERMALINK + sha,
    }


def as_analyzer_result(sha256: str, api_key: str) -> AnalyzerResult:
    """Map a VirusTotal verdict onto the engine's Signal vocabulary.

    Verdict → signal:

    * ``>= 5`` engines malicious → ``high``  ``intel.vt_malicious``
    * ``1``–``4`` engines malicious → ``medium`` ``intel.vt_malicious``
    * seen, none malicious (some suspicious) → ``low`` ``intel.vt_suspicious``
    * seen, nothing flagged → ``info`` ``intel.vt_seen_clean``
    * unknown hash → ``info`` ``intel.vt_unknown`` (explicitly *not* benign)
    * no key → ``AnalyzerResult.unavailable(...)``
    """
    if not api_key:
        return AnalyzerResult.unavailable(ANALYZER_NAME, "VT_API_KEY not set")

    verdict = lookup(sha256, api_key)

    if verdict.get("error"):
        # A refusal is not a failure and must not read as one — "lookup failed"
        # would tell an operator their key is broken when in fact their own
        # policy stopped the call.
        return AnalyzerResult.unavailable(
            ANALYZER_NAME, verdict.get("refusal") or f"lookup failed: {verdict['error']}"
        )

    if not verdict.get("found"):
        signal = Signal(
            id="intel.vt_unknown",
            title="Hash unknown to VirusTotal",
            severity="info",
            detail=(
                "VirusTotal has no record of this SHA-256. Unknown is not the "
                "same as clean — a novel or targeted sample is unknown by "
                "definition."
            ),
            evidence={"sha256": sha256},
        )
        return AnalyzerResult(
            analyzer=ANALYZER_NAME,
            ran=True,
            signals=[signal],
            facts={"found": False},
        )

    malicious = verdict["malicious"]
    suspicious = verdict["suspicious"]
    permalink = verdict["permalink"]
    evidence = {
        "sha256": sha256,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": verdict["harmless"],
        "undetected": verdict["undetected"],
        "reputation": verdict["reputation"],
        "permalink": permalink,
    }

    if malicious >= 5:
        signal = Signal(
            id="intel.vt_malicious",
            title=f"Flagged malicious by {malicious} VirusTotal engines",
            severity="high",
            detail=f"{malicious} engines flag this hash as malicious.",
            evidence=evidence,
        )
    elif malicious >= 1:
        signal = Signal(
            id="intel.vt_malicious",
            title=f"Flagged malicious by {malicious} VirusTotal engines",
            severity="medium",
            detail=(
                f"{malicious} engine(s) flag this hash as malicious — a low "
                "count, but non-zero."
            ),
            evidence=evidence,
        )
    elif suspicious >= 1:
        signal = Signal(
            id="intel.vt_suspicious",
            title=f"Marked suspicious by {suspicious} VirusTotal engines",
            severity="low",
            detail=f"{suspicious} engine(s) mark this hash as suspicious.",
            evidence=evidence,
        )
    else:
        signal = Signal(
            id="intel.vt_seen_clean",
            title="Known to VirusTotal, no engine flags it",
            severity="info",
            detail=(
                "VirusTotal has seen this hash and no engine currently flags "
                "it. Reputation only — not a guarantee."
            ),
            evidence=evidence,
        )

    return AnalyzerResult(
        analyzer=ANALYZER_NAME,
        ran=True,
        signals=[signal],
        facts=evidence,
        iocs=IOCs(hashes=[sha256], urls=[permalink]),
    )
