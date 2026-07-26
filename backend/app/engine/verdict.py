"""Internal multi-engine verdict — a VirusTotal-style consensus computed in-house.

VirusTotal shows one row per antivirus vendor. We do not call thirty vendors;
instead each of our own analysis modules — every static analyzer, every matched
YARA rule, the heuristic capability model, IOC reputation, and VirusTotal itself
when a key is configured — is treated as a "detection engine". Each either flags
the sample (with a short detection name) or clears it, and the panel reports the
detection ratio and a consensus verdict.

The threat is also given a classification name in the familiar
``Platform.Category.Family`` shape, derived transparently from the sample's type
and its strongest observed capability. It is a description of what was seen, not
a claim to recognise a specific named strain.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .capabilities import detect as detect_capabilities
from .contracts import SEVERITY_ORDER, AnalyzerResult, IOCs

_FLAGGING = {"medium", "high", "critical"}

# --- classification vocabulary -----------------------------------------------
_SCRIPT_PLATFORM = {
    "text/x-powershell": "PowerShell",
    "text/javascript": "JS",
    "text/vbscript": "VBS",
    "text/x-msdos-batch": "Batch",
    "text/x-python": "Python",
    "text/x-shellscript": "Shell",
    "application/hta": "HTA",
}
_FAMILY_PLATFORM = {
    "pe": "Win32", "elf": "Linux", "office": "Office", "pdf": "PDF",
    "apk": "Android", "jar": "Java", "diskimage": "DiskImage", "archive": "Archive",
}

#: capability -> category, in priority order (first match wins). Ordered the way
#: an analyst names a strain: impact first, then the most recognisable behaviour.
#: First match wins, so this is ordered by how strongly the capability defines
#: what the sample IS. Ransom and Exploit can only come from the dynamic tier —
#: static evidence never demonstrates them, and claiming otherwise is how a
#: password-protected document got classified as ransomware.
_CATEGORY_BY_CAP = [
    ("destruction", "Ransom"),
    ("credential", "Spyware"),
    ("exploit", "Exploit"),
    ("network", "Downloader"),
    ("injection", "Injector"),
    ("persistence", "Backdoor"),
    ("dropper", "Dropper"),
    ("execution", "Trojan"),
    ("privilege", "Riskware"),
    ("deception", "Riskware"),
    ("discovery", "Riskware"),
]

_ENGINE_LABELS = {
    "generic": "CS-Static/Generic",
    "pe": "CS-Static/PE",
    "elf": "CS-Static/ELF",
    "office": "CS-Static/Office",
    "script": "CS-Static/Script",
    "pdf": "CS-Static/PDF",
    "apk": "CS-Static/Android",
    "jar": "CS-Static/Java",
    "diskimage": "CS-Static/DiskImage",
    "archive": "CS-Static/Archive",
    "virustotal": "VirusTotal",
}


@dataclass
class VerdictResult:
    verdict: str                       # malicious | suspicious | clean
    threat_name: str                   # Platform.Category.Family
    detection_ratio: str               # "7 / 11"
    detected: int = 0
    total_engines: int = 0
    platform: str = ""
    category: str = ""
    family: str = ""
    engines: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "threat_name": self.threat_name,
            "detection_ratio": self.detection_ratio,
            "detected": self.detected,
            "total_engines": self.total_engines,
            "platform": self.platform,
            "category": self.category,
            "family": self.family,
            "engines": self.engines,
        }


def _platform(family: str, mime: str) -> str:
    if family == "script":
        return _SCRIPT_PLATFORM.get(mime, "Script")
    return _FAMILY_PLATFORM.get(family, "Generic")


def _family_token(signals: list) -> str:
    if not signals:
        return "Gen"
    top = max(signals, key=lambda s: SEVERITY_ORDER.get(s.severity, 0))
    tail = top.id.split(".")[-1] if "." in top.id else top.id
    token = "".join(p.capitalize() for p in tail.replace("-", "_").split("_"))
    return (token or "Agent")[:20]


def _worst(signals: list) -> str:
    if not signals:
        return "info"
    return max(signals, key=lambda s: SEVERITY_ORDER.get(s.severity, 0)).severity


def classify(
    family: str,
    mime: str,
    results: Iterable[AnalyzerResult],
    iocs: IOCs | None,
    final_score: float,
) -> VerdictResult:
    results = list(results)
    all_signals = [s for r in results if r.ran for s in r.signals]
    caps = detect_capabilities(all_signals, iocs)

    platform = _platform(family, mime)
    category = next((cat for cap, cat in _CATEGORY_BY_CAP if cap in caps), None)
    #: A file we found no capability in is not "Suspicious" — it is a file we
    #: found nothing in. Naming it after its worst informational signal is how
    #: a Microsoft-signed binary became "Win32.Downloader.TimestampAnomaly".
    if category is None:
        category = "Clean"
    fam = _family_token(all_signals)
    threat_name = f"{platform}.{category}.{fam}" if category != "Clean" else f"{platform}.Clean"

    # Build the engine panel.
    engines: list[dict[str, Any]] = []
    for result in results:
        if not result.ran:
            continue
        name = _ENGINE_LABELS.get(result.analyzer)
        if result.analyzer == "yara":
            # Expand each matched rule as its own detection row.
            for sig in result.signals:
                engines.append({
                    "engine": f"CS-YARA/{sig.id.split('.')[-1]}",
                    "detected": True,
                    "result": sig.title,
                    "severity": sig.severity,
                })
            if not result.signals:
                engines.append({"engine": "CS-YARA", "detected": False, "result": "undetected", "severity": "info"})
            continue
        if name is None:
            name = f"CS-{result.analyzer}"
        worst = _worst(result.signals)
        flagged = worst in _FLAGGING
        engines.append({
            "engine": name,
            "detected": flagged,
            "result": f"{platform}.{category}.{fam}" if flagged else "undetected",
            "severity": worst,
        })

    # Heuristic capability engine: fires on demonstrated capability.
    engines.append({
        "engine": "CS-Heuristic",
        "detected": bool(caps),
        "result": threat_name if caps else "undetected",
        "severity": _worst(all_signals) if caps else "info",
    })
    # Reputation engine. It must key off indicators that are themselves *bad*
    # (an IP-literal URL, a lookalike domain, a suspicious TLD) — not off the
    # mere existence of a URL. Counting "this file contains a link" as a
    # detection made every README and every PDF invoice a second detection,
    # which alone pushed them over the malicious threshold.
    reputation_ids = {
        "generic.ip_literal_url",
        "generic.suspicious_tld",
        "generic.punycode_or_lookalike_domain",
        "generic.many_urls",
    }
    bad_rep = [s for s in all_signals if s.id in reputation_ids]
    engines.append({
        "engine": "CS-Reputation",
        "detected": bool(bad_rep),
        "result": "Suspicious.Indicator" if bad_rep else "undetected",
        "severity": _worst(bad_rep) if bad_rep else "info",
    })

    detected = sum(1 for e in engines if e["detected"])
    total = len(engines)

    # The verdict and the score are two views of the same evidence, so they are
    # not allowed to contradict each other. Previously a sample could be called
    # malicious while its own score said 1.8/100 "low" — the single most
    # trust-destroying thing this product could put in front of an analyst.
    # The score bands are authoritative; the engine count can only corroborate.
    # "Malicious" additionally requires that we can NAME what the sample does.
    # If no capability was demonstrated we have a pile of unexplained anomalies,
    # which is "suspicious" — reporting malicious there produced the absurd pair
    # verdict=malicious / threat=Win32.Clean in the same payload.
    if caps and final_score >= 60:
        verdict = "malicious"
    elif caps and final_score >= 30 and detected >= 2:
        verdict = "malicious"
    elif final_score >= 30 or (detected >= 1 and caps):
        verdict = "suspicious"
    else:
        verdict = "clean"

    return VerdictResult(
        verdict=verdict,
        threat_name=threat_name,
        detection_ratio=f"{detected} / {total}",
        detected=detected,
        total_engines=total,
        platform=platform,
        category=category,
        family=fam,
        engines=engines,
    )
