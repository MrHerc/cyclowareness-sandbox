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

from .contracts import SEVERITY_ORDER, IOCs, AnalyzerResult, Signal, risk_level

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
    # Does this container carry a program? THREE analyzers answer, on the same
    # bytes, and each one banded separately — so one fact contributed three
    # times. An ISO holding a signed copy of PuTTY came out `malicious` at 56.6
    # on nothing else: `generic.embedded_executable`,
    # `diskimage.embedded_executable` and `yara.embedded_pe_in_nonpe`, all high,
    # all saying "there is an executable inside".
    "generic.embedded_executable": "carries-a-program",
    "diskimage.embedded_executable": "carries-a-program",
    "yara.embedded_pe_in_nonpe": "carries-a-program",
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


#: Behaviours that ordinary Windows software performs as part of working.
#:
#: The dynamic tier imports CAPE's own severity verbatim, and CAPE's signature
#: set is tuned to flag anything unusual INSIDE A VM. A signed GUI installer run
#: in a VM trips a dozen of them at medium or high, and the bands then add up to
#: "suspicious" without a single accusing capability behind it. Measured on 50
#: benign samples — 7-Zip, PuTTY, Audacity, HandBrake, WinMerge, Greenshot, the
#: Python embeddable distribution, Sysinternals — 30 of them were not clean, and
#: the reason was always a stack of these rather than any one finding.
#:
#: What each of these actually is:
#:
#:   query_fips_reconnaissance          reading the crypto policy at startup
#:   privilege_elevation_check          asking whether it is elevated (UAC)
#:   antisandbox_system_parameters_info SystemParametersInfo — desktop metrics
#:   antisandbox_windows_activation     reading the activation state
#:   mouse_movement_detect              a GUI waiting for input
#:   per_file_acl_token_check           an installer checking it may write
#:   reads_self                         a self-extractor reading its own file
#:   contains_pe_overlay                an installer's appended payload
#:   *mount*                            choosing which drive to install on
#:   *tls_callback*, *deep_entrypoint*  how MSVC and packers build binaries
#:   packer_*, section_vsize_anomaly    compression, which installers all use
#:   hardware_id_profiling              licensing and telemetry
#:   interprocess_comms_shared_memory   ordinary IPC
#:   suspicious_iocontrol_codes         measured FP: raised by Windows Update
#:                                      in a different branch of the process tree
#:
#: They are demoted to `low`, NOT removed: an analyst still sees every one of
#: them in the report, and one of them beside real evidence still reads as part
#: of the picture. What stops is a pile of them adding up to an accusation.
#:
#: EVERY MEMBER WAS MEASURED. Against the 88-malware detonation fixture this set
#: costs ZERO detections (84 of 88 before and after). Three candidates were
#: REJECTED for costing one each: `pe.overlay_present` and
#: `generic.high_entropy_overall` both lose WannaCry, and
#: `capev2.pe_exports_in_executable` loses RaccoonStealer. Two more were rejected
#: for weakening detection to buy two benign files: `capev2.persistence_autorun`
#: and `capev2.mass_file_modification_access` are the persistence and ransomware
#: signals, and a malware sandbox does not trade those away.
AMBIENT_SIGNALS = frozenset({
    # environment the program was started in
    "capev2.query_fips_reconnaissance",
    "capev2.privilege_elevation_check",
    "capev2.antisandbox_system_parameters_info",
    "capev2.antisandbox_windows_activation",
    "capev2.mouse_movement_detect",
    "capev2.per_file_acl_token_check",
    # what an installer does to install
    "capev2.reads_self",
    "capev2.contains_pe_overlay",
    "capev2.discover_registry_mount_points",
    "capev2.mountpoints_volume_discovery",
    "capev2.mountpoint_manager_access",
    # how the binary was built
    "pe.tls_callbacks",
    "capev2.pe_tls_callbacks",
    "capev2.antianalysis_tls_section",
    "capev2.pe_deep_entrypoint",
    "capev2.packer_unknown_pe_section_name",
    "capev2.packer_entropy",
    "capev2.pe_section_vsize_rsize_anomaly",
    "capev2.registers_vectored_exception_handler",
    "capev2.allocated_memory_protection_noaccess",
    # ordinary application behaviour
    "capev2.hardware_id_profiling",
    "capev2.interprocess_comms_shared_memory",
    "capev2.network_connection_via_suspicious_process",
    "capev2.suspicious_iocontrol_codes",
    # a container that contains things
    "archive.contains_executable",
    # --- what an administrative tool does, added 2026-07-30 ------------------
    #
    # Sysinternals, NirSoft and UPX read as `suspicious` because a diagnostics
    # tool's whole job is the thing CAPE flags: Process Explorer verifies the
    # Authenticode signature of every running process (`modify_certs`), loads a
    # helper driver (`driver_load`), lists processes and their modules
    # (`createtoolhelp32snapshot_module_enumeration`), and reads a
    # Zone.Identifier stream (`persistence_ads`).
    #
    # SELECTED BY A STATED RULE, not by what happened to be free: a signal is
    # demoted only if it is NO MORE COMMON IN MALWARE than in ordinary software,
    # measured as incidence across the 50-sample benign corpus and the 88-sample
    # detonation fixture. Twenty-five candidates were swept; all twenty-five cost
    # zero fixture detections, and ten were still REJECTED because they lean
    # malware and demoting them would trade real capability for nothing:
    #
    #   antivm_wmi                  0% benign  18% malware
    #   encrypted_ioc              12%         19%
    #   uses_windows_utilities      4%         15%
    #   interprocess_comms_mutex    4%         15%
    #   enumerates_running_processes 4%        14%
    #   suspicious_ntdll_disk_load 10%         17%
    #   recon_fingerprint           4%          7%
    #   recon_systeminfo            2%          4%
    #   process_interest            2%          6%
    #   cmdline_http_link           2%          3%
    #
    # The fifteen below all run the other way. Measured: benign 20 of 50 clean
    # -> 23, fixture 84 of 88 -> 84. The principled fifteen buy exactly what the
    # greedy twenty-five did.
    "capev2.modify_certs",
    "capev2.driver_load",
    "capev2.sysinternals_tools",
    "capev2.recon_programs",
    "capev2.persistence_ads",
    "capev2.createtoolhelp32snapshot_module_enumeration",
    "capev2.deletes_executed_files",
    "capev2.anomalous_deletefile",
    "capev2.antivm_display",
    "capev2.antivm_generic_system",
    "capev2.antivm_generic_disk",
    "capev2.antivm_generic_services",
    "capev2.dllload_suspicious_directory",
    "capev2.multiple_useragents",
    "capev2.network_bind",
})


#: Signals that name a *capability* rather than an intent.
#:
#: Evaluating a string as code is what a template engine, a bundler, a REPL and
#: a test runner all do — Vue's runtime compiler is literally
#: `const render = new Function(code)()`. What a dropper cannot avoid is ALSO
#: fetching, decoding or hiding the string it evaluates, and those are separate
#: signals. So this counts in full whenever anything else in its family is
#: raised, and counts as `low` when it is the only thing we have.
#:
#: Deliberately not a "this file says it is a published library" waiver: a
#: banner comment is one line for an attacker to forge, whereas needing the
#: payload from somewhere is structural.
#:
#: signal id -> the id prefix whose other raised signals corroborate it.
CAPABILITY_NEEDS_CORROBORATION: dict[str, str] = {
    "script.dynamic_execution": "script.",
}


#: Facts about how a binary was BUILT, not about what it does.
#:
#: Every one of these is produced by an ordinary compiler, linker, installer
#: builder or commercial packer, and an unsigned lookalike produces every one of
#: them identically. They are the reason Process Explorer, WinMerge, Audacity,
#: Greenshot, the Python distribution and a dozen release archives read as
#: `suspicious`, and no amount of tuning separates them from a loader, because
#: THERE IS NOTHING IN THE BYTES THAT DIFFERS.
#:
#: What does differ is who signed them. So these stop accusing — and only these
#: — when `pe.signature_verified` is present: the Authenticode signature covers
#: these exact bytes, the signer's key verifies it, the chain is
#: cryptographically linked, and it reaches an anchor this deployment trusts.
#:
#: `generic.high_entropy_overall` and `pe.overlay_present` are in this list even
#: though both were REJECTED from `AMBIENT_SIGNALS` for losing WannaCry. That is
#: not a contradiction — it is the point. WannaCry is not signed. Demoting them
#: for everything costs a detection; demoting them only for a verified publisher
#: costs nothing, and that is what a real discriminator buys.
#:
#: Behaviour is deliberately absent. A stolen certificate is stolen precisely to
#: buy a waiver, ten of the malware samples on the detonation host are signed,
#: and no signature will ever excuse what a program was watched doing.
STRUCTURAL_SIGNALS = frozenset({
    "generic.high_entropy_overall",
    "pe.high_entropy_section",
    "pe.section_size_anomaly",
    "pe.packer_section_name",
    "pe.writable_executable_section",
    "pe.overlay_present",
    "pe.few_imports",
    "pe.import_combination",
    "pe.timestamp_anomaly",
    "pe.compile_timestomping",
    "pe.tls_callbacks",
    "yara.upx_packed_executable",
    "capev2.pe_writable_executable_section",
    "capev2.static_pe_anomaly",
    "capev2.packer_entropy",
    "capev2.packer_unknown_pe_section_name",
    "capev2.pe_section_vsize_rsize_anomaly",
    "capev2.pe_deep_entrypoint",
    "capev2.contains_pe_overlay",
    "capev2.pe_compile_timestomping",
})

#: The signal that switches the waiver on. One id, so there is one place to look.
VERIFIED_PUBLISHER_SIGNAL = "pe.signature_verified"

#: Signals that describe the INTERPRETER, not the script it was handed.
#:
#: Detonating a `.ps1` runs powershell.exe, which loads AMSI on startup and whose
#: .NET JIT emits code into unbacked memory — that is what a JIT IS. Measured
#: across every PowerShell script detonated on this host, INCLUDING ripgrep's and
#: fd's shell-completion scripts, which define a few functions and exit:
#:
#:     signal                                          on .ps1   on PE   fixture
#:     capev2.unbacked_api_resolution                     100%     22%      45%
#:     capev2.unbacked_library_load                       100%     23%      45%
#:     capev2.unbacked_dotnet_execution                   100%      6%      19%
#:     capev2.amsi_enumeration                            100%     12%      25%
#:     capev2.creates_suspended_process                    100%     38%      58%
#:     capev2.resumethread_remote_process                  100%     38%      59%
#:     ... twelve more `unbacked_*` at 100%
#:
#: A signal that fires on 100% of a population cannot distinguish within it. It
#: made `_rg.ps1` — a tab-completion script — `malicious` at 45.9, which made
#: ripgrep's release archive malicious too.
#:
#: This is keyed on FAMILY and not global, because the same observation means
#: something real about a PE: unbacked code execution in a compiled binary is
#: manual mapping or a reflective loader, and it fires on only 6-23% of them.
#:
#: Priced against every script-shaped malware sample on the detonation host — 17
#: files, 36 stored analyses of them: **0 lost**. Thirty-four stay `malicious`;
#: two move from `malicious` to `suspicious`. The 88-sample fixture cannot price
#: this, because it contains no scripts at all.
FAMILY_AMBIENT_SIGNALS: dict[str, frozenset[str]] = {
    "script": frozenset({
        # powershell.exe / wscript.exe starting up and spawning a child
        "capev2.creates_suspended_process",
        "capev2.resumethread_remote_process",
        "capev2.reads_memory_remote_process",
        "capev2.terminates_remote_process",
        # AMSI is loaded by the host, not requested by the script
        "capev2.amsi_enumeration",
        # every one of these is the .NET JIT: unbacked memory is where it emits
        "capev2.unbacked_api_resolution",
        "capev2.unbacked_library_load",
        "capev2.unbacked_memory_protection_alteration",
        "capev2.unbacked_process_mitigation_alteration",
        "capev2.unbacked_token_manipulation",
        "capev2.unbacked_dotnet_execution",
        "capev2.unbacked_crypto_operations",
        "capev2.unbacked_com_instantiation",
        "capev2.unbacked_file_dropping",
        "capev2.unbacked_process_enumeration",
        "capev2.unbacked_privilege_escalation",
        "capev2.unbacked_mutex_creation",
    }),
}


def family_ambient(family: str | None) -> frozenset[str]:
    return FAMILY_AMBIENT_SIGNALS.get((family or "").lower(), frozenset())


#: Families whose DYNAMIC signals are recorded, timelined and shown — and never
#: scored, and never allowed to name a capability.
#:
#: `FAMILY_AMBIENT_SIGNALS` above lists ids, which works when the signals are
#: known and only some of them are noise. This is the other case: a platform
#: whose whole dynamic signal set is uncalibrated, where enumerating ids would
#: be guessing at a list that upstream changes.
#:
#: `elf` is here because Linux detonation was measured before it was enabled:
#:
#:   * CAPE loads `modules/signatures/all/` for a Linux task as well as the four
#:     in `linux/`, and `all/stealth_network.py` fires whenever the report has
#:     network hosts and no `network`-category call was seen. The strace
#:     processor emits category `net`, never `network`, so it is a GUARANTEED
#:     false positive on any Linux task with a PCAP.
#:   * `capev2.deletes_files` arrives at CAPE severity 3, which this engine maps
#:     to `high`, on any `unlink` or `O_TRUNC`.
#:   * Not one Linux id appears in `AMBIENT_SIGNALS`, `STRUCTURAL_SIGNALS` or
#:     `FAMILY_AMBIENT_SIGNALS`, and there is no benign Linux corpus to build
#:     those lists from the way the 50-sample Windows corpus built them.
#:
#: Together that means the first flagged Linux sample would most likely read
#: `Linux.Backdoor.DeletesFiles` because it truncated a file, pushed over the
#: threshold by the guest's own DNS traffic. That is the exact false-positive
#: disease this engine spent a corpus curing on PDF and on static ELF, and
#: shipping it on a platform with no fixture would be doing it deliberately.
#:
#: So the detonation runs, the syscall trace is captured, the timeline and every
#: signal are in the report and in the signed evidence — and none of it moves
#: the number. A trace is a document until it is calibrated.
#:
#: TO REMOVE A FAMILY FROM HERE: build a benign corpus for that platform, run
#: it, and populate the demotion lists from what fires on software that is not
#: malware. That is the same bar every other platform cleared.
DYNAMIC_UNCALIBRATED_FAMILIES = frozenset({"elf"})


def uncalibrated_dynamic_ids(family: str | None, signals: "Iterable[Signal]") -> frozenset[str]:
    """Dynamic signal ids that may not assert anything, because the platform
    they came from has never been measured against benign software.

    Empty for every calibrated family, so a caller can apply it unconditionally.

    Its own function because it has three consumers that want DIFFERENT things
    around it: `capability_exclusions` adds `uncorroborated` and
    `family_ambient`, while the two `mitre.map_techniques` callers want this
    term alone — a blanket severity gate on ATT&CK was measured and rejected at
    a cost of 362 techniques, 28 of them on malicious samples. Written out
    inline it was already four copies, and copies of this exact decision have
    drifted twice.
    """
    if not dynamic_uncalibrated(family):
        return frozenset()
    return frozenset(s.id for s in signals if _dynamic(s.id))


def capability_exclusions(
    family: str | None,
    signals: "Iterable[Signal]",
    *,
    attributable: bool = True,
) -> frozenset[str]:
    """Signal ids that must never reach `detect_capabilities`.

    ONE DEFINITION, BECAUSE THIS HAS DRIFTED ONCE ALREADY. `verdict.classify`
    and `impact.assess` both build a capability set, and `impact.assess` said in
    its own comment that its exclusions were "verdict.py's, deliberately and
    exactly". They were, until `verdict.classify` gained a third term for
    uncalibrated platforms and `impact.assess` did not.

    Measured on the deployed image, same static findings, once alone and once
    with the first real Linux detonation folded in:

        family elf   impact 0.0 / none   ->   5.3 / medium
                     capabilities +Network / C2, +Carries an executable payload
        family pe    identical numbers, i.e. the guard had NO effect at all

    `detect_capabilities` reads `signal.severity`, not `effective_severity`, so
    forcing an uncalibrated platform's signals to `info` does nothing here — and
    the impact rating travels inside the Ed25519-signed evidence bundle at
    `report.reproducible.impact`.

    The four terms:

    * `uncorroborated` — a lone high-consequence signal is a lead, not a finding;
    * `family_ambient` — the interpreter is not the sample;
    * every dynamic id when the platform is uncalibrated — a syscall trace from
      a platform nobody has measured against benign software is a document;
    * every dynamic id when the detonation is NOT ATTRIBUTABLE — see below.

    THE SECOND AXIS. There are two unrelated reasons a detonation may be shown
    and may not accuse, and the guard was built for only one of them:

      calibration      the platform's signatures were never measured (`elf`);
      attributability  Windows cannot execute this file at all, so whatever the
                       guest did, this sample did not do it.

    `scoring.assess` has taken `dynamic_attributable` since the 226 inert files
    were detonated, and honours it: measured on the live image, a `script` with
    three `capev2` signals scores `rule=7.0` not-attributable against `98.0`
    attributable. Every OTHER consumer took the calibration axis and stopped.
    So the same trace that the score refuses to count still reached the verdict
    through the identification branch:

        script / text/html, README.html, three capev2 signals + capev2.detection
        -> verdict MALICIOUS, threat Script.Malware.Ryuk, SandboxID
           detected=True severity=critical, at a final_score of 5.9

    A man page came out `T1055 Process Injection` by the same route. The score
    breakdown says "Windows has no way to run a file of this type… excluded from
    the score" three keys away from the verdict that used it.

    Why a symmetry test could not catch it: `test_a_second_path_forgot_the_rule`
    asserts the pipeline and the report handler pass the SAME arguments to
    `impact.assess` and `verdict.classify`. They did. Both were equally wrong.

    `AMBIENT_SIGNALS` is deliberately NOT among them: it is demoted for scoring
    only, and routing it into the capability engine was measured at a cost of 16
    fixture detections.
    """
    signals = list(signals)
    inadmissible = uncalibrated_dynamic_ids(family, signals)
    if not attributable:
        inadmissible |= frozenset(s.id for s in signals if _dynamic(s.id))
    return frozenset(uncorroborated(signals) | family_ambient(family) | inadmissible)


def uncalibrated_note(family: str | None, signals: "Iterable[Signal]") -> dict | None:
    """The sentence a report owes an analyst when a trace is shown but not believed.

    Nothing said so anywhere. Every guard in this module is invisible outside it:
    on the nine ELF jobs that have really detonated, no surface — the JSON API,
    the React UI, the PDF case file, the STIX bundle, the DORA/NIS2 record or the
    Ed25519-signed evidence — contains a word about calibration.

    AND THE ROWS DO NOT LOOK DEMOTED. `effective_severity` is a scoring function;
    it does not rewrite the stored signal, and it must not — CAPE reported
    `deletes_files` at severity 3 and a signed artifact has to keep saying so.
    The consequence is that the PDF prints `[high] Deletes files from disk` in
    the exported case file while that same row contributes 0.0 to the score,
    names no capability, sets no verdict and maps to no technique. A reader has
    no way to tell those two facts apart, and the report never mentions that
    there is anything to tell apart.

    The regulatory record was worse than silent. `incident._evidence` fell back
    to the literal "All configured analysis tiers ran." — every tier HAD run, so
    the sentence was true and the impression it left was not.

    Deliberately NOT a severity rewrite. The fix is to explain the row, not to
    edit the evidence.

    Lives in `scoring` because the guard test forbids `capev2.` from appearing in
    pipeline.py, api/dynamic.py, verdict.py and impact.py — one definition of
    what an uncalibrated platform may assert, in one module.
    """
    ids = uncalibrated_dynamic_ids(family, signals)
    if not ids:
        return None
    return {
        "family": (family or "").lower(),
        "signal_count": len(ids),
        "reason": (
            "The behavioural findings in this report were observed on a platform "
            "whose signature set this deployment has not yet measured against "
            "benign software. They are recorded in full, and excluded from the "
            "score, the capability list, the threat name and the ATT&CK mapping "
            "— including any row shown below at medium or high severity. The "
            "severities are the sandbox's own and have been left untouched."
        ),
    }


def inadmissible_dynamic_ids(
    family: str | None,
    signals: "Iterable[Signal]",
    *,
    attributable: bool = True,
) -> frozenset[str]:
    """Dynamic ids that may not be concluded from — on EITHER axis.

    Narrower than `capability_exclusions` on purpose, and the difference matters.
    The ATT&CK mapping wants only this: `capability_exclusions` also carries
    `uncorroborated` and `family_ambient`, and routing those into technique
    mapping would quietly drop techniques from real malware that this change has
    no business touching.
    """
    signals = list(signals)
    ids = uncalibrated_dynamic_ids(family, signals)
    if not attributable:
        ids |= frozenset(s.id for s in signals if _dynamic(s.id))
    return ids


def dynamic_uncalibrated(family: str | None) -> bool:
    """Is this family's dynamic tier observed but not yet believed?"""
    return (family or "").lower() in DYNAMIC_UNCALIBRATED_FAMILIES


def scorable_ioc_total(
    results: "Iterable[AnalyzerResult]",
    family: str | None,
    *,
    attributable: bool = True,
) -> int:
    """How many indicators the SCORE is allowed to count.

    Not the same number as the report shows. `job.iocs` keeps every indicator
    the analysis produced, including the trace's, because a Linux detonation
    that resolved a domain is evidence worth reading even when nothing may be
    concluded from it — this only decides what reaches `ioc_density`.

    It exists because the guard leaked a fifth way. `assess` takes `ioc_total`,
    feeds it to the `ioc_density` term (model weight 0.9) and so into `ai_score`
    and `final_score`, and both callers computed it by merging every analyzer's
    indicators, dynamic tier included. Measured on the live image: an ELF whose
    trace contributed 25 indicators scored 26.2 against the same sample's 24.0
    static-only — 2.2 points, from a tier every other consumer ignores. It
    survived the guard's tests because `rule_score` never moves (37.0 in both),
    and those tests asserted on `rule_score`.

    Shared rather than fixed twice on purpose: the same duplication between
    `verdict.classify` and `impact.assess` is what let the rating leak into the
    signed evidence after the score had already been fixed.
    """
    merged = IOCs()
    #: Both axes, for the same reason `capability_exclusions` carries both: a C2
    #: address the guest reached while "running" an HTML readme is the guest's,
    #: not the sample's, and 12 such indicators were still reaching `ioc_density`.
    skip_dynamic = dynamic_uncalibrated(family) or not attributable
    for result in results:
        if not result.ran:
            continue
        if skip_dynamic and result.analyzer.startswith("dynamic."):
            continue
        merged = merged.merge(result.iocs)
    return merged.total()


#: Prefixes of the signals a detonation produces.
_DYNAMIC_PREFIX = "capev2."


def _dynamic(signal_id: str) -> bool:
    return signal_id.startswith(_DYNAMIC_PREFIX)


def publisher_verified(signals: Iterable[Signal]) -> bool:
    return any(s.id == VERIFIED_PUBLISHER_SIGNAL for s in signals)


def uncorroborated(signals: Iterable[Signal]) -> frozenset[str]:
    """Ids from `CAPABILITY_NEEDS_CORROBORATION` that stand alone in `signals`."""
    raised = list(signals)
    alone: set[str] = set()
    for signal_id, prefix in CAPABILITY_NEEDS_CORROBORATION.items():
        if not any(s.id == signal_id for s in raised):
            continue
        if not any(
            s.id != signal_id
            and s.id.startswith(prefix)
            and s.severity in ("medium", "high", "critical")
            for s in raised
        ):
            alone.add(signal_id)
    return frozenset(alone)


def effective_severity(
    signal: Signal,
    alone: frozenset[str] = frozenset(),
    *,
    verified_publisher: bool = False,
    family: str | None = None,
    dynamic_attributable: bool = True,
) -> str:
    """The severity this signal carries INTO the score.

    Everything an analyzer or a sandbox reported is kept and shown; this is only
    about what may push a verdict. See `AMBIENT_SIGNALS`,
    `CAPABILITY_NEEDS_CORROBORATION` (`alone` comes from `uncorroborated()`),
    `STRUCTURAL_SIGNALS` (`verified_publisher` from `publisher_verified()`) and
    `FAMILY_AMBIENT_SIGNALS` (`family` — the interpreter is not the script).
    """
    # A detonation on a platform whose signal set has never been measured
    # against benign software observed something real and cannot yet say what it
    # means. See DYNAMIC_UNCALIBRATED_FAMILIES for the measurements behind this.
    #
    # `info`, NOT `low`: `info` weighs 0.0, which is what "recorded, not counted
    # against the file" already means elsewhere here (`pdf.open_action`,
    # `pdf.embedded_file`). Deliberately stricter than the `dynamic_attributable`
    # rule below, which stops at `low` — that one is about ONE sample that could
    # not execute, this is about a whole platform nobody has calibrated.
    #
    # And it sits BEFORE the early return below, because that return is what a
    # `low` signal hits first and `low` weighs 4, not 0.
    #
    # Measured twice on the same sample. Demoting only medium/high/critical took
    # it from 31.4 to 31.1 against a static-only 29.5 — the two signals CAPE
    # itself reported at `low` (`stealth_network`, `reads_files`) never reached
    # the rule at all and kept contributing. An uncalibrated platform has to
    # contribute nothing whatever severity it arrives at.
    if _dynamic(signal.id) and dynamic_uncalibrated(family):
        return "info"
    if signal.severity not in ("medium", "high", "critical"):
        return signal.severity
    if signal.id in AMBIENT_SIGNALS or signal.id in alone:
        return "low"
    if verified_publisher and signal.id in STRUCTURAL_SIGNALS:
        return "low"
    if family and signal.id in family_ambient(family):
        return "low"
    # A detonation of something that cannot execute observed the GUEST, not the
    # sample. The observations are kept and shown — an analyst can see exactly
    # what the guest did — but they may not accuse a file that never ran.
    if not dynamic_attributable and _dynamic(signal.id):
        return "low"
    return signal.severity


def rule_score(
    signals: Iterable[Signal],
    *,
    family: str | None = None,
    dynamic_attributable: bool = True,
) -> tuple[float, list[dict[str, Any]]]:
    """Severity-weighted rule score in 0-100, plus the per-band arithmetic."""
    bands: dict[str, list[Signal]] = {}
    kept = _collapse_correlated(list(signals))
    alone = uncorroborated(kept)
    signed = publisher_verified(kept)
    for signal in kept:
        bands.setdefault(
            effective_severity(
                signal, alone, verified_publisher=signed, family=family,
                dynamic_attributable=dynamic_attributable,
            ), [],
        ).append(signal)

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


#: Shannon entropy over bytes cannot exceed 8. Anything outside [0, 8] is not an
#: entropy measurement, it is a number that arrived in a `facts` dict.
_MAX_ENTROPY = 8.0


def _as_entropy(value: Any) -> float:
    """A facts value read as entropy, or 0.0 if it is not one.

    `facts` is free-form and one of its writers is an off-host worker, so this
    reads attacker-adjacent input. Two values crashed it: a bare `float(value)`
    on an integer too large for a float raises **OverflowError** — measured, a
    worker report with `max_section_entropy` set to a 400-digit integer took the
    ingest to a 500, and because the job stayed `completed` the queue offered it
    to the worker again on every poll, forever — and a non-finite float sailed
    through every comparison downstream until it reached the score.

    Clamping rather than raising is deliberate here: a nonsense entropy is a
    nonsense feature, not a reason to lose a detonation that cost a guest and
    four minutes. `assess` still refuses to return a non-finite score, so a
    genuinely corrupt pipeline is still loud.

    Anything that is not a finite measurement contributes NOTHING — `inf` and
    `NaN` both read as 0.0 rather than as the maximum. The direction matters:
    `max_entropy` is a feature that pushes the score UP, so mapping garbage to
    8.0 would let whatever wrote that dict inflate a verdict by sending a value
    that is not a number. A missing measurement is not evidence.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    try:
        number = float(value)
    except (OverflowError, ValueError):
        # An integer too large to be a float. Not a measurement either.
        return 0.0
    if not math.isfinite(number):
        return 0.0
    return max(0.0, min(_MAX_ENTROPY, number))


def extract_features(results: Iterable[AnalyzerResult], signals: list[Signal], ioc_total: int) -> Features:
    results = list(results)
    ids = [s.id for s in signals]

    yara = sum(1 for i in ids if i.startswith("yara."))

    entropy = 0.0
    for result in results:
        facts = result.facts or {}
        for key in ("max_section_entropy", "entropy", "overall_entropy"):
            entropy = max(entropy, _as_entropy(facts.get(key)))
        for section in facts.get("sections", []) or []:
            if isinstance(section, dict):
                entropy = max(entropy, _as_entropy(section.get("entropy")))

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


#: Only the ratio matters, so this expresses every split anyone could want — and
#: two values at the bound still sum to a finite number, which is the property
#: actually doing the work. See the second failure described below.
MAX_WEIGHT = 1e6


def set_weights(rule_weight: float, model_weight: float) -> dict[str, float]:
    """Set the rule/model split. Rejects anything that cannot produce a ratio.

    The finiteness check comes first, and the ordering is the whole fix: `NaN`
    satisfied every comparison this function used to make — `nan <= 0` is False,
    and so is `nan < 0` — so it passed validation, normalised to `nan / nan`,
    and left the process weights non-finite. After that `GET /api/admin/weights`,
    `/api/capabilities` and the signed export all returned 500, because
    Starlette hard-codes `allow_nan=False`, and every later submission computed
    a non-finite `final_score`. On SQLite that raised and left jobs stuck at
    `queued` with `error = NULL`; on Postgres it is worse, because
    `'NaN'::double precision` is a value it accepts — the row PERSISTS, and
    `GET /api/jobs` then fails for every analyst in the tenant, surviving both
    `weights/reset` and a restart.

    The ceiling exists for the mirror image of the same problem. `1e308 + 1e308`
    overflows to `inf`, both weights normalise to `0.0`, and the endpoint
    returned 200 for precisely the `{0, 0}` state it raises on when asked for it
    directly — after which every verdict read 0.0 / low beside its own unchanged
    rule_score, impact rating and high-severity reasons.
    """
    # Coerced first, and inside the guard. Python integers are unbounded, so
    # `math.isfinite(10**400)` does not answer False — it raises OverflowError,
    # which is an ArithmeticError and not a ValueError, so it escaped both this
    # function's contract and the 422 the API turns a ValueError into. A caller
    # who skips pydantic (a script, a test, the tuning code) got a 500 from the
    # validator itself.
    try:
        rule_weight = float(rule_weight)
        model_weight = float(model_weight)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("weights must be finite numbers") from exc
    if not (math.isfinite(rule_weight) and math.isfinite(model_weight)):
        raise ValueError("weights must be finite numbers")
    if rule_weight < 0 or model_weight < 0:
        raise ValueError("weights must be non-negative and sum to a positive number")
    if rule_weight > MAX_WEIGHT or model_weight > MAX_WEIGHT:
        raise ValueError(f"each weight must be at most {MAX_WEIGHT:g}")
    total = rule_weight + model_weight
    if total <= 0:
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
    family: str | None = None,
    dynamic_attributable: bool = True,
) -> Assessment:
    results = list(results)
    signals = [s for r in results if r.ran for s in r.signals]

    # `family` is optional so every existing caller and test keeps working; when
    # it is absent nothing is family-demoted, which is the stricter direction.
    rules, rule_detail = rule_score(
        signals, family=family, dynamic_attributable=dynamic_attributable
    )
    # The same three inputs `rule_score` just used, so the headline reasons below
    # are ranked by what actually moved the number.
    alone = uncorroborated(signals)
    signed = publisher_verified(signals)
    features = extract_features(results, signals, ioc_total)
    ai, contributions = model_score(features)
    weights = get_weights()
    final = round(weights["rule"] * rules + weights["model"] * ai, 1)

    # A non-finite score must never reach a row. `set_weights` is now the only
    # way one could be introduced and it refuses to, so this is the second line
    # rather than the first — but the failure it prevents is not proportionate
    # to any bug that could cause it. Postgres accepts `'NaN'::double precision`
    # and `final_score` is double precision, so a single poisoned row makes
    # `GET /api/jobs` fail for every analyst in that tenant, permanently, and
    # survives a restart because it is in the database rather than in memory.
    # Failing this one job loudly, with the reason on the row, is recoverable.
    if not math.isfinite(final):
        raise ValueError(
            f"refusing to store a non-finite score (rule={rules!r}, ai={ai!r}, "
            f"weights={weights!r}) — a scoring input is corrupt"
        )

    #: The top three reasons, in the words the analyzers used. This is what the
    #: PDF's executive summary and the UI headline both read from, so there is
    #: exactly one answer to "why".
    #:
    #: RANKED BY THE SEVERITY THAT ACTUALLY SCORED, not the raw one. Sorting on
    #: `s.severity` ignored all four demotions, so a signature-verified 7-Zip
    #: installer whose rule score had already demoted `hardware_id_profiling` and
    #: `reads_self` to `low` still printed them in the PDF as
    #: "1. HIGH — Hardware ID profiling", in red, beside a `low` risk band and a
    #: `clean` verdict. `verdict.py` fixed exactly this for `_worst` and
    #: `_family_token`; the headline reasons were the third place it was wrong.
    #: The reported severity is the effective one for the same reason.
    ranked = sorted(
        signals,
        key=lambda s: -SEVERITY_ORDER.get(
            effective_severity(
                s, alone, verified_publisher=signed, family=family,
                dynamic_attributable=dynamic_attributable,
            ), 0
        ),
    )
    top = [
        {
            "id": s.id,
            "title": s.title,
            "severity": effective_severity(
                s, alone, verified_publisher=signed, family=family,
                dynamic_attributable=dynamic_attributable,
            ),
            "detail": s.detail[:300],
        }
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
