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

from .capabilities import HIGH_CONSEQUENCE
from .capabilities import detect as detect_capabilities

#: Capabilities that justify calling a file a detection rather than a
#: description. Discovery, evasion, execution and network are true of ordinary
#: software; destruction, credential theft, exploitation and code injection are
#: not.
#:
#: This is exactly the set the capability model already holds to a higher
#: evidentiary standard, and it is an alias rather than a second list so the two
#: cannot drift apart — a detection threshold and an evidence threshold that
#: disagree is how a sample gets accused of something the report does not show.
ACCUSING_CAPABILITIES = HIGH_CONSEQUENCE
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

def _category_for(caps: set[str], signals: list) -> str | None:
    """The headline category: the capability the evidence actually leans on.

    A fixed priority order alone gets this visibly wrong. Formbook is an
    infostealer, and a real detonation of it produced dozens of credential and
    injection signals against a couple of wiper-categorised ones — yet
    `destruction` sits first in the list, so the report read
    `Win32.Ransom.Formbook`. Anyone who knows the family reads that as the
    product not knowing what it is looking at, and they are half right.

    So: weigh each candidate capability by how many signals support it, and let
    the priority order break ties. A sample that really is ransomware still
    produces overwhelmingly destructive evidence and still comes out `Ransom`;
    one that merely touched a volume on its way to stealing passwords does not.
    """
    from .capabilities import detect as _detect

    if not caps:
        return None
    ranked = [(cap, cat) for cap, cat in _CATEGORY_BY_CAP if cap in caps]
    if not ranked:
        return None

    # Only HIGH-severity signals count toward support. Weighing every signal
    # equally was measurably worse than the plain priority order: discovery is
    # the most common thing any program does, so raw counts crowned `Riskware`
    # on WannaCry. Severity is what separates "touched a volume" from "encrypted
    # the disk".
    support: dict[str, int] = {}
    for signal in signals:
        if SEVERITY_ORDER.get(signal.severity, 0) < SEVERITY_ORDER["high"]:
            continue
        for cap in _detect([signal]):
            support[cap] = support.get(cap, 0) + 1

    # Priority still leads; support only overrides it when another capability has
    # clearly more high-severity evidence. Two is the margin: one stray signal
    # should not rename a family.
    lead_cap, lead_cat = ranked[0]
    lead = support.get(lead_cap, 0)
    for cap, cat in ranked[1:]:
        if support.get(cap, 0) >= lead + 2:
            lead_cap, lead_cat, lead = cap, cat, support[cap]
    return lead_cat


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
    """The family half of the threat name.

    A sandbox that identified the family by name is the best source there is, so
    it wins outright. Without one, the name is derived from the worst signal —
    which is a description of a behaviour, not a family, and reads badly: a real
    WannaCry detonation was named `Win32.Ransom.HardwareIdProfiling`, and Emotet
    (a loader) came out as `Win32.Ransom.AntisandboxUnhook`. That is the honest
    fallback rather than a fabricated family, but prefer the real answer.
    """
    if not signals:
        return "Gen"
    for signal in signals:
        evidence = getattr(signal, "evidence", None) or {}
        fam = evidence.get("family") if isinstance(evidence, dict) else None
        if fam:
            token = "".join(p for p in str(fam) if p.isalnum())
            if token:
                return token[:20]
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
    category = _category_for(caps, all_signals)
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
        if result.analyzer.startswith("dynamic."):
            # A detonation ALWAYS produces medium-or-worse signals — every
            # program that runs performs discovery, touches the registry and
            # trips an evasion-categorised rule or two. Counting "we ran it and
            # saw activity" as a detection therefore handed every detonated
            # sample a guaranteed extra engine hit, which with an ordinary risk
            # score is enough to reach `malicious`.
            #
            # Measured on 107 real samples through the full pipeline: 86 of 87
            # malware caught, and **all five signed installers called malicious**
            # — 7-Zip, WinMerge, Python, PuTTY, Notepad++ — with
            # `CS-dynamic.capev2` firing on every one of them.
            #
            # Behaviour is not detection. This row now fires on the same standard
            # as the heuristic engine: an accusing capability demonstrated by the
            # behaviour it observed.
            observed = detect_capabilities(result.signals, None)
            flagged = bool(observed & ACCUSING_CAPABILITIES)
        else:
            flagged = worst in _FLAGGING
        engines.append({
            "engine": name,
            "detected": flagged,
            "result": f"{platform}.{category}.{fam}" if flagged else "undetected",
            "severity": worst,
        })

    # Heuristic capability engine. It fires on a capability worth *accusing* a
    # sample of - not on any capability at all.
    #
    # Firing on `caps` was wrong and measurably so: every program performs
    # discovery, every installer evades nothing in particular but trips evasion
    # signatures, and both are in `caps`. On a real corpus that made a signed
    # 7-Zip installer, Notepad++ and PuTTY all come out "malicious", because one
    # heuristic detection plus an ordinary risk score crosses the threshold.
    # Injection is included because it is the one behavioural capability the
    # benign corpus never demonstrated at high severity.
    accusing = caps & (ACCUSING_CAPABILITIES)
    engines.append({
        "engine": "CS-Heuristic",
        "detected": bool(accusing),
        "result": threat_name if accusing else "undetected",
        "severity": _worst(all_signals) if accusing else "info",
    })

    # Sandbox identification. Distinct from every engine above, because those
    # reason about what a sample *did* and this one is about what it *is*: a
    # named family, an extracted configuration block, or a YARA rule matching
    # known malware in process memory.
    #
    # It exists because behaviour alone misses a sample that never got going.
    # Locky, detonated here, produced eight signatures and no capability — its
    # C2 was long dead so it never encrypted anything — and scored zero. The
    # sandbox still matched it in memory. Measured across 8 malware and 3 signed
    # installers, this fired 8/8 and 0/3, while the sandbox's own aggregate
    # score did not separate them at all.
    identification = [
        s
        for s in all_signals
        if (getattr(s, "evidence", None) or {}).get("family")
        or (
            SEVERITY_ORDER.get(s.severity, 0) >= SEVERITY_ORDER["high"]
            and "malware" in {
                str(c).lower()
                for c in ((getattr(s, "evidence", None) or {}).get("categories") or [])
            }
        )
    ]
    named = next(
        (
            (getattr(s, "evidence", None) or {}).get("family")
            for s in identification
            if (getattr(s, "evidence", None) or {}).get("family")
        ),
        None,
    )
    engines.append({
        "engine": "CS-SandboxID",
        "detected": bool(identification),
        "result": (f"{platform}.{category}.{fam}" if named else "Sandbox.MemoryMatch")
        if identification
        else "undetected",
        "severity": _worst(identification) if identification else "info",
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
    # Identification outranks the score. A sandbox matching known malware in
    # process memory, or recovering a family's configuration block, is an
    # identity claim - "this IS Locky" - not a behavioural guess, and it does not
    # get weaker because the sample failed to do much. Locky detonated here with
    # a long-dead C2: it encrypted nothing, demonstrated no accusing capability
    # and scored 39, and it is still unmistakably Locky.
    if identification:
        verdict = "malicious"
    elif caps and final_score >= 60:
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
