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

from dataclasses import dataclass, field, replace
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
    from .capabilities import evidence_capabilities as _evidence

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
    #
    # Support is measured with `evidence_capabilities`, not `detect`. This asks
    # what each signal is ABOUT, which is a different question from what the
    # report may accuse the sample of: `detect` requires corroboration, so a
    # lone signal never yields a high-consequence capability and every
    # destruction signal would score zero support. That renamed WannaCry
    # `Win32.Downloader.WanaCry` and Formbook `Win32.Riskware.Formbook`.
    support: dict[str, int] = {}
    for signal in signals:
        if SEVERITY_ORDER.get(signal.severity, 0) < SEVERITY_ORDER["high"]:
            continue
        for cap in _evidence(signal):
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
    #: Set when a container inherited a worse verdict from something inside it.
    raised_because: str = ""

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
            **({"raised_because": self.raised_because} if self.raised_because else {}),
        }

    def raised_to(self, verdict: str, *, because: str) -> "VerdictResult":
        """The same assessment, escalated by something this sample contains.

        A container is judged on its own signals, and a container has almost
        none — carrying files is not a capability. The escalation therefore
        comes from outside `classify`, from the pipeline, which is the only
        place that knows about children. It is recorded rather than silently
        applied: a reader has to be able to see that the word changed and why.
        """
        category = _CATEGORY_FOR_VERDICT.get(verdict, self.category)
        threat_name = ".".join(
            [self.platform or "Generic", category or "Suspicious", self.family or "Gen"]
        )
        # AND THE ROWS MOVE WITH IT.
        #
        # `classify` stamps every row that reports a detection with the sample's
        # name — that is its stated rule — and this method rebuilds the name
        # without touching them. Measured on the live deployment, one panel
        # carried both at once:
        #
        #     headline             Archive.Malware.PowershellDownloadCr
        #     CS-archive-contents  Archive.Suspicious.PowershellDownloadCr
        #
        # Two names for one file, side by side. Only rows whose `result` IS the
        # old name are restamped: a YARA row carries the matched rule's own
        # description, which `classify` also leaves alone, and an `undetected`
        # row is not reporting a name at all.
        engines = [
            {**row, "result": threat_name}
            if row.get("result") == self.threat_name
            else dict(row)
            for row in self.engines
        ]
        return replace(
            self,
            verdict=verdict,
            category=category,
            threat_name=threat_name,
            engines=engines,
            raised_because=because[:300],
        )


#: The category half of the threat name, when the verdict was raised from a
#: member rather than derived from this sample's own capabilities.
_CATEGORY_FOR_VERDICT = {"malicious": "Malware", "suspicious": "Suspicious"}

#: Categories that accuse the sample of being a kind of malware. `Riskware` is
#: absent on purpose — it is the honest word for a dual-use tool, and it is what
#: a verified publisher's ambiguous evidence is renamed to.
_ACCUSING_CATEGORIES = frozenset({
    "Ransom", "Spyware", "Exploit", "Downloader", "Injector", "Backdoor",
    "Dropper", "Trojan",
})


def _platform(family: str, mime: str) -> str:
    if family == "script":
        return _SCRIPT_PLATFORM.get(mime, "Script")
    return _FAMILY_PLATFORM.get(family, "Generic")


def _family_token(signals: list, family: str | None = None) -> str:
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
    # Named from the worst signal that is allowed to DRIVE a verdict, not the
    # worst one present. Otherwise the score and the label disagreed about the
    # same file: 7-Zip's own installer scored as ordinary software and was still
    # headlined `Win32.Riskware.HardwareIdProfiling`, after the score had
    # already decided that reading a hardware id is what licensed software does.
    from .scoring import effective_severity, publisher_verified, uncorroborated

    alone = uncorroborated(signals)
    signed = publisher_verified(signals)
    ranked = sorted(
        signals,
        key=lambda s: -SEVERITY_ORDER.get(
            effective_severity(s, alone, verified_publisher=signed, family=family), 0
        ),
    )
    top = ranked[0]
    tail = top.id.split(".")[-1] if "." in top.id else top.id
    token = "".join(p.capitalize() for p in tail.replace("-", "_").split("_"))
    return (token or "Agent")[:20]


def _worst(
    signals: list,
    family: str | None = None,
    *,
    dynamic_attributable: bool = True,
) -> str:
    """The worst severity that may drive an engine's verdict.

    Reads `scoring.effective_severity`, not `signal.severity`, so an ambient
    sandbox signature cannot be the most severe thing in a report. Otherwise the
    score said "clean" and the engine panel still headlined the file with
    `hardware_id_profiling` at high — one number and one label disagreeing about
    the same sample.

    AND THE SAME SENTENCE APPLIES ONE AXIS OVER. `effective_severity` takes two
    independent guards, and this function forwarded only one of them: `family`
    carries the calibration axis, and `dynamic_attributable` — "Windows cannot
    run this file, so the guest's behaviour is the guest's" — was left at its
    default of True. So on a sample the engine had already decided may not
    accuse, the `CS-dynamic.capev2` row published the raw CAPE severity.

    Measured over the 839 detonated jobs on the live deployment: 90 engine rows
    stored `high` where the score had banded every one of their signals `low`.
    One of them is a file called LICENSE. The signed evidence bundle for it
    carries, three keys apart, `"severity": "high"` on the row and a
    `dynamic_not_attributable` block stating those findings are "excluded from
    the score" — the same document asserting both.

    Invisible on screen, because the UI hides the chip on an undetected row.
    Present in every machine-readable artifact, which is the half that leaves
    the building.
    """
    if not signals:
        return "info"
    from .scoring import effective_severity, publisher_verified, uncorroborated

    alone = uncorroborated(signals)
    signed = publisher_verified(signals)
    return max(
        (effective_severity(
            s, alone,
            verified_publisher=signed,
            family=family,
            dynamic_attributable=dynamic_attributable,
        ) for s in signals),
        key=lambda sev: SEVERITY_ORDER.get(sev, 0),
    )


def _evidence_group(signal_id: str) -> str | None:
    """Which correlated-evidence group a signal belongs to, if any.

    Shared with the scoring model so the two cannot disagree about what counts
    as one fact. A signal that scores once must also detect once — if they drift,
    a fact suppressed in the score comes back as an extra engine in the panel.
    """
    from .scoring import EVIDENCE_GROUPS

    return EVIDENCE_GROUPS.get(signal_id)


def classify(
    family: str,
    mime: str,
    results: Iterable[AnalyzerResult],
    iocs: IOCs | None,
    final_score: float,
    *,
    attributable: bool = True,
) -> VerdictResult:
    results = list(results)
    all_signals = [s for r in results if r.ran for s in r.signals]
    # A capability standing on its own is not an accusation. Vue's runtime
    # template compiler is literally `new Function(code)()`, which asserted
    # `injection` and headlined the library `JS.Injector.DynamicExecution` — at
    # a risk score of 6.6, the panel and the number disagreeing about the same
    # file. See `scoring.CAPABILITY_NEEDS_CORROBORATION`: the demotion has to
    # reach the capability engine too, or the score says clean and the engine
    # row still detects.
    # A SIGNAL THAT DESCRIBES THE INTERPRETER CANNOT ASSERT A CAPABILITY OF THE
    # SCRIPT, for the same reason.
    #
    # `detect_capabilities` is severity-blind, so the `unbacked_*` cluster —
    # demoted to `low` because it fires on 100% of PowerShell detonations,
    # including tab-completion scripts — still yielded `injection`. The panel
    # then contradicted itself: `fd.ps1` scored 6.1, every engine row carried
    # severity `low`, and two rows still read DETECTED, so the file came out
    # `suspicious` and took fd.zip with it.
    #
    # Deliberately narrow. `AMBIENT_SIGNALS` is demoted FOR SCORING ONLY by
    # design and is NOT filtered here: routing it into the capability engine was
    # measured and took the detonation fixture from 84 of 88 to 68.
    # `FAMILY_AMBIENT_SIGNALS` makes a different claim — not "ordinary software
    # does this too" but "this is the interpreter, not the sample" — and a
    # capability the sample does not have is not a capability.
    from .scoring import capability_exclusions, publisher_verified, uncorroborated

    alone = uncorroborated(all_signals)
    signed = publisher_verified(all_signals)
    # A PLATFORM WE HAVE NOT CALIBRATED CANNOT NAME A CAPABILITY.
    #
    # Demoting these in `effective_severity` keeps them out of the SCORE, and
    # `detect_capabilities` is severity-blind — the same asymmetry that let the
    # `unbacked_*` cluster yield `injection` while every row read `low`. Without
    # the exclusion a Linux detonation would still produce a threat name and a
    # category out of signals the score is deliberately ignoring, and the panel
    # would contradict the number in exactly the documented way.
    # `capev2.deletes_files` alone would read `Linux.Backdoor.DeletesFiles`.
    #
    # Computed by `scoring.capability_exclusions` rather than assembled here, so
    # `impact.assess` cannot go on using a different set — which it did, and the
    # rating leaked into the signed evidence for it.
    excluded = capability_exclusions(family, all_signals, attributable=attributable)
    #: Every consumer below reads THIS, not `all_signals`. Applying the exclusion
    #: to `caps` alone was not enough, and the sweep found the gap three ways in
    #: one function: `_family_token` still read the excluded signals' evidence,
    #: so an uncalibrated Linux detonation named the family anyway; `identification`
    #: was built from `all_signals`, and `if identification: verdict = "malicious"`
    #: outranks the score — so a trace the score is ignoring completely still
    #: decided the verdict, at `final_score` 0.0, with the CS-SandboxID row
    #: reading `detected: true` beside `severity: info`. Measured on the live
    #: image before the fix: an ELF carrying `capev2.detection.mirai` came out
    #: `malicious / Linux.Malware.Mirai` with a score of nothing at all.
    admissible = [s for s in all_signals if s.id not in excluded] if excluded else all_signals
    caps = detect_capabilities(admissible, iocs)

    platform = _platform(family, mime)
    category = _category_for(caps, admissible)
    #: A file we found no capability in is not "Suspicious" — it is a file we
    #: found nothing in. Naming it after its worst informational signal is how
    #: a Microsoft-signed binary became "Win32.Downloader.TimestampAnomaly".
    if category is None:
        category = "Clean"
    fam = _family_token(admissible, family)
    threat_name = f"{platform}.{category}.{fam}" if category != "Clean" else f"{platform}.Clean"

    # Build the engine panel.
    engines: list[dict[str, Any]] = []
    for result in results:
        if not result.ran:
            continue
        name = _ENGINE_LABELS.get(result.analyzer)
        if result.analyzer == "yara":
            # Expand each matched rule as its own detection row.
            #
            # A ROW IS A DETECTION ONLY IF THE ENGINE DID NOT ALREADY DEMOTE IT.
            #
            # `detected` was hard-coded True, so a match the YARA engine itself
            # had marked as not-evidence still counted — including the two cases
            # it demotes ON PURPOSE:
            #
            #   * `not_for = <this family>`, whose own detail says "this match is
            #     reported but does not count as evidence";
            #   * `_CONTAINER_RULES` on an .msi/.iso, demoted to `low` because an
            #     installer carrying a program is what an installer IS.
            #
            # PuTTY's official MSI barely moved the score for exactly that reason
            # and still landed a DETECTED row against it.
            #
            # The bar is MEDIUM, not the `high` the static rows use, and the
            # difference is deliberate. A static row is a structural fact —
            # entropy, an overlay, TLS callbacks — which every self-extracting
            # installer trips at medium, so medium there means nothing. A YARA
            # rule is a specific statement about specific bytes. Measured on the
            # 88-sample fixture: 12 of its 17 YARA signals are medium, and
            # requiring `high` cost njrat its verdict on
            # `powershell_stealth_flags` and `js_obfuscation_eval_decode` —
            # taking malicious from 69 to 67, through the floor. Demoted rows are
            # exactly `info` and `low`, so that is where the line belongs.
            for sig in result.signals:
                if sig.id == "yara.match_cap_reached":
                    # Bookkeeping, not a match. It says how many rules fired.
                    engines.append({
                        "engine": "CS-YARA", "detected": False,
                        "result": sig.title, "severity": "info",
                    })
                    continue
                row = {
                    "engine": f"CS-YARA/{sig.id.split('.')[-1]}",
                    "detected": (
                        SEVERITY_ORDER.get(sig.severity, 0) >= SEVERITY_ORDER["medium"]
                    ),
                    "result": sig.title,
                    "severity": sig.severity,
                }
                if not row["detected"]:
                    row["result"] = f"{sig.title} (reported, not counted as a detection)"
                group = _evidence_group(sig.id)
                if group:
                    row["evidence_group"] = group
                engines.append(row)
            if not result.signals:
                engines.append({"engine": "CS-YARA", "detected": False, "result": "undetected", "severity": "info"})
            continue
        if name is None:
            name = f"CS-{result.analyzer}"
        # THE ONE CALL THAT SEES RAW DYNAMIC SIGNALS. Every other `_worst` call
        # in this function is handed a list the exclusions have already been
        # applied to (`admissible`, `identification`, static-only reputation
        # ids); this one is the analyzer's own list, so it is the only place the
        # attributability axis has to be threaded by hand.
        worst = _worst(result.signals, family, dynamic_attributable=attributable)
        if result.analyzer.startswith('dynamic.'):
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
            # The SAME exclusion as the consensus capability set above, or this
            # row contradicts it. It read the raw signals, so after
            # `FAMILY_AMBIENT_SIGNALS` stopped the interpreter's own behaviour
            # asserting `injection` for the verdict, this row went on asserting
            # it anyway — `fd.ps1` scored 6.1 with every row at severity `low`
            # and `CS-dynamic.capev2` still reading DETECTED.
            observed = detect_capabilities(
                [s for s in result.signals if s.id not in excluded], None
            )
            flagged = bool(observed & ACCUSING_CAPABILITIES)
        else:
            # Static rows need HIGH, not medium. Every self-extracting
            # installer trips high entropy, an overlay and TLS callbacks at
            # medium - structural facts about how installers are built, not
            # findings. Measured: that alone was flagging 7-Zip, WinMerge,
            # Python and Notepad++ as detections.
            flagged = worst in {'high', 'critical'}
        row = {
            "engine": name,
            "detected": flagged,
            "result": f"{platform}.{category}.{fam}" if flagged else "undetected",
            "severity": worst,
        }
        # A row is attributed to an evidence group only when EVERY signal that
        # could have flagged it belongs to that group. A PE analyzer that fired
        # on packing and on something else is a genuinely separate opinion, and
        # collapsing it would hide a real second finding.
        if flagged:
            deciding = [
                s for s in result.signals
                if SEVERITY_ORDER.get(s.severity, 0) >= SEVERITY_ORDER["high"]
            ] if not result.analyzer.startswith("dynamic.") else []
            groups = {_evidence_group(s.id) for s in deciding}
            if deciding and len(groups) == 1 and None not in groups:
                row["evidence_group"] = groups.pop()
        engines.append(row)

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
        # `all_signals`, so the same axis has to be passed here. Zero live rows
        # are wrong today — `accusing` is empty on every job that carries
        # `dynamic_not_attributable` — which makes this the latent half of the
        # same defect rather than a second one, and exactly the kind that ships
        # the day a capability set widens.
        "severity": (
            _worst(all_signals, family, dynamic_attributable=attributable)
            if accusing else "info"
        ),
    })

    # Sandbox identification. Distinct from every engine above, because those
    # reason about what a sample *did* and this one is about what it *is*: a
    # named family, or an extracted configuration block. Both are identity
    # claims a benign program cannot manufacture — configuration extraction
    # succeeds only against the real family, and a family name is the sandbox
    # saying it recognises the strain.
    #
    # It exists because behaviour alone misses a sample that never got going: a
    # loader whose C2 is dead does almost nothing, and still is what it is.
    #
    # It used to ALSO fire on any high-severity signal the sandbox filed under
    # the category "malware", which in practice meant CAPE's `procmem_yara` —
    # "a YARA rule matched somewhere in the analysis". That is not an identity
    # claim, and reading it as one made a signed release of WinMerge malicious.
    # The rule it matched was `embedded_macho`, which fires on three 4-byte
    # magics (`CA FE BA BE`, `CE FA ED FE`, `FE ED FA CE`) appearing anywhere
    # except offset 0 — a coincidence in any multi-megabyte dump, and it hit in
    # a file the installer had legitimately written to disk. CAPE's own
    # `detections` field was empty: the sandbox never claimed to know what it
    # was, we inferred it from the signature's category.
    #
    # That is the same mistake as the three before it, in a fourth costume:
    # counting an observation as a detection. A rule matched is an observation.
    # It still raises the score; it no longer decides the verdict.
    # An identity claim from an UNCALIBRATED platform is still only a claim.
    # This reads `admissible` for the same reason the score does: the Linux
    # signature set has never been measured against a corpus here, and an
    # identification is the most confident thing the product can say. If CAPE
    # mis-names a Linux sample, reading it from `all_signals` publishes
    # `malicious / Linux.<Family>` off a tier whose every other output is
    # deliberately ignored. The signal is still recorded and shown in full — as
    # with the 226 inert detonations, the evidence is kept and simply may not
    # accuse. Cost of the exclusion on this deployment, measured rather than
    # assumed: of 9 ELF samples that really detonated, 0 carry a family
    # identification and 0 carry a config, so no verdict changes today.
    identification = [
        s for s in admissible if (getattr(s, "evidence", None) or {}).get("family")
    ]
    engines.append({
        "engine": "CS-SandboxID",
        "detected": bool(identification),
        "result": f"{platform}.{category}.{fam}" if identification else "undetected",
        "severity": _worst(identification, family) if identification else "info",
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
        "severity": _worst(bad_rep, family) if bad_rep else "info",
    })

    # Count distinct EVIDENCE, not distinct rows.
    #
    # A detection panel is only worth reading if its rows are independent
    # opinions, and they are not always. A UPX-packed binary trips the PE
    # analyzer's entropy and section-size checks AND a UPX YARA rule, so "this is
    # packed" arrives as two engines agreeing when it is one fact seen twice.
    # Under `caps and final_score >= 30 and detected >= 2` that pair alone
    # reaches `malicious` — which is how Rufus, a signed disk utility, got there
    # with no accusing capability at all.
    #
    # Rows resting entirely on one correlated evidence group count once. The
    # panel still SHOWS every row: an analyst should see that both detectors
    # noticed, and should not be told they are two independent findings.
    counted_groups: set[str] = set()
    detected = 0
    for entry in engines:
        if not entry["detected"]:
            continue
        group = entry.get("evidence_group")
        if group is not None:
            if group in counted_groups:
                continue
            counted_groups.add(group)
        detected += 1
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
    # Identification outranks the score. A sandbox naming the family, or
    # recovering its configuration block, is an identity claim - "this IS
    # Formbook" - not a behavioural guess, and it does not get weaker because the
    # sample failed to do much: a loader whose C2 is dead does almost nothing and
    # is still what it is.
    # A document that DESCRIBES attack behaviour is never clean, and never worse
    # than suspicious.
    #
    # The script analyzer downgrades its capability claims for files the OS does
    # not execute — a README explaining `curl … | bash` is text about a program,
    # not a program — which is what stopped rclone's README.txt being MALICIOUS
    # at CIR 8.8. But the other end needs saying too: the same downgrade made a
    # working PowerShell dropper renamed `instructions.txt` come out CLEAN at
    # 12.8, and "clean" is a wrong answer for a file full of working attack code.
    #
    # So: the findings are notes rather than capabilities, and the verdict is
    # capped at suspicious rather than floored at clean. Neither end pretends.
    #
    # TWO, for the same reason two conclusive signals are needed to accuse a
    # sample of destruction. Almost every README mentions `curl` once, and a
    # product where every README is "suspicious" has taught its analysts to
    # ignore the word. A document that describes remote payload retrieval AND
    # dynamic execution AND persistence is not documentation that happens to
    # mention a tool — it is a set of instructions.
    prose_findings = {s.id for s in all_signals if s.id.startswith("document.mentions_")}
    describes_an_attack = len(prose_findings) >= 2

    if identification:
        verdict = "malicious"
    elif caps and final_score >= 60:
        verdict = "malicious"
    elif caps and final_score >= 30 and detected >= 2:
        verdict = "malicious"
    elif final_score >= 30 or (detected >= 1 and caps) or describes_an_attack:
        verdict = "suspicious"
    else:
        verdict = "clean"

    # THE NAME HAS TO AGREE WITH THE VERDICT.
    #
    # `threat_name` is derived from the capabilities, up at the top of this
    # function; `verdict` is decided down here from the score and the panel.
    # Nothing reconciled them, so the report showed both and they disagreed —
    # measured on this deployment, **43 of 200 clean jobs carried a name that
    # accused them**, including Microsoft-signed Sysinternals tools:
    #
    #     PsGetsid.exe   clean   Win32.Downloader.OverlayPresent   20.7
    #     tcpview.exe    clean   Win32.Downloader.TlsCallbacks     21.8
    #     autorunsc.exe  clean   Win32.Downloader.TlsCallbacks     22.4
    #
    # A green "Clean" badge beside the word "Downloader" on Microsoft's own
    # signed binary. This is the same mistake this file already fixed once, in
    # another costume — see the comment on `category is None` above: naming a
    # sample after its worst informational signal. An overlay, TLS callbacks and
    # high entropy are how installers are built, not what they do.
    #
    # The mirror case is just as wrong and was also present: 17 suspicious jobs
    # and 1 malicious job named `<Platform>.Clean`, a verdict that flags the
    # sample beside a name that clears it.
    #
    # A clean verdict makes no claim, so it gets no claim in its name.
    if verdict == "clean":
        category = "Clean"
        threat_name = f"{platform}.Clean"
    elif category == "Clean":
        # Flagged, but no capability was named — usually a sandbox identifying
        # the family without this engine deriving a category from it. Say which
        # of the two it is rather than borrow the word "Clean".
        category = "Malware" if verdict == "malicious" else "Suspicious"
        threat_name = f"{platform}.{category}.{fam}"
    elif verdict == "suspicious" and signed and category in _ACCUSING_CATEGORIES:
        # A VERIFIED PUBLISHER IS NOT A BACKDOOR ON AMBIGUOUS EVIDENCE.
        #
        # Process Explorer installs a helper driver as a service, which really is
        # an autorun, so `capev2.persistence_autorun` fires — and that signal is
        # pinned as never-demote, because it is the persistence signal and a
        # malware sandbox does not trade it away. The verdict `suspicious` is
        # therefore correct and stays.
        #
        # The NAME was not. `Win32.Backdoor.PersistenceAutorun` on a binary whose
        # Authenticode signature verifies to Microsoft Code Signing PCA 2024 says
        # the product does not know what it is looking at. When the publisher is
        # established and the evidence only reached `suspicious`, the honest word
        # for a dual-use tool is `Riskware` — which is what commercial engines
        # call Sysinternals too.
        #
        # Deliberately narrow: `malicious` keeps its accusing category, because
        # signed malware exists and eight of the samples on this host are signed.
        # This changes a label, never a score and never a verdict.
        category = "Riskware"
        threat_name = f"{platform}.{category}.{fam}"

    # Every row that reports a detection reports the sample's name, so they move
    # with it. YARA rows are excluded on purpose: theirs is the matched rule's
    # own description, which is a different and more useful thing to show.
    for row in engines:
        if (
            row.get("detected")
            and not str(row.get("engine", "")).startswith("CS-YARA")
            and row.get("result") not in ("undetected", "Suspicious.Indicator")
        ):
            row["result"] = threat_name

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
