"""What a sample can *do*, distilled from the signals the analyzers fired.

One shared taxonomy so the impact rating, the threat classification and the
MITRE ATT&CK mapping all reason about the same observed capabilities rather
than re-deriving them three different ways.

Two rules make this trustworthy, and both exist because violating them produced
a 90% false-positive rate on ordinary business files:

1. **Match exact signal ids, never substrings of free text.** A signal's ``id``
   is its stable machine identifier (``office.autoexec_macro``); its ``title``
   is prose written for a human. Substring-matching prose is how ``"rop"``
   matched inside *ent-rop-y* and turned every high-entropy installer into an
   "Exploit", and how ``"encrypt"`` matched ``office.encrypted`` — a
   password-protected document — and reported it as ransomware.

2. **A capability is something the sample can DO, not something it mentions.**
   A PDF containing a hyperlink has not communicated with anything; a document
   that fetches a remote template on open has. Passive string evidence still
   raises the rule score, but it must never assert a capability, because
   capabilities drive the impact vector and the threat classification.

Info-severity signals are neutral facts (``pe.signature_present`` means the
binary is *signed* — a good sign) and never assert a capability.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .contracts import SEVERITY_ORDER, IOCs, Signal

#: Below this severity a signal is a fact, not a capability.
_MIN_SEVERITY = SEVERITY_ORDER["low"]

#: capability -> the exact signal ids that demonstrate it.
#: Every id here is emitted by a real analyzer; nothing is speculative.
CAPABILITY_SIGNALS: dict[str, frozenset[str]] = {
    # The sample can cause code to run.
    "execution": frozenset({
        "office.autoexec_macro", "office.xlm_macro", "office.dde_field", "office.vba_present",
        "pdf.launch_action", "pdf.open_action", "pdf.javascript",
        "jar.runtime_exec",
        "apk.suspicious_api",
        "diskimage.autorun",
        "script.download_and_execute", "script.dynamic_execution",
        "script.encoded_command", "script.execution_policy_bypass",
    }),
    # The sample actively reaches out. Passive URLs in strings are NOT this.
    "network": frozenset({
        "office.remote_template",
        "pdf.submit_form",
        "script.download_and_execute",
    }),
    # The sample reads secrets or personal data.
    "credential": frozenset({
        "script.credential_access",
        "apk.dangerous_permission",
    }),
    # The sample survives a reboot / re-runs itself.
    "persistence": frozenset({
        "script.persistence",
        "diskimage.autorun",
    }),
    # The sample hides from analysis or disables defences.
    "evasion": frozenset({
        "pe.packer_section_name",
        "elf.packed",
        "office.macro_obfuscation", "office.vba_stomping",
        "pdf.object_stream_obfuscation",
        "jar.obfuscated",
        "script.obfuscation_high", "script.defense_evasion",
        "script.amsi_or_etw_tamper", "script.hidden_window", "script.decoded_layer",
    }),
    # The sample loads or runs code that is not statically visible.
    # pe.import_combination (not the individual import groups, which are facts
    # present in ordinary software) is what argues for this on a PE.
    "injection": frozenset({
        "pe.writable_executable_section", "pe.import_combination",
        "jar.classloader", "jar.reflection", "jar.script_engine",
        "apk.dynamic_code",
        "script.dynamic_execution",
    }),
    # The sample carries another executable payload.
    "dropper": frozenset({
        "generic.embedded_executable",
        "diskimage.embedded_executable",
        "archive.contains_executable",
        "pdf.embedded_file", "office.embedded_object",
    }),
    # The sample abuses elevation / device-administration controls.
    "privilege": frozenset({
        "apk.accessibility_abuse",
    }),
    # The sample disguises what it is.
    "deception": frozenset({
        "generic.extension_mismatch",
        "archive.double_extension",
        "diskimage.suspicious_filename",
        "generic.punycode_or_lookalike_domain",
        "archive.path_traversal",
    }),
    #: Deliberately empty: no analyzer produces evidence of destructive or
    #: exploitation behaviour today. Claiming either from static evidence we do
    #: not have is exactly the dishonesty this engine refuses. They stay as keys
    #: so the dynamic tier can populate them once a sample is actually detonated.
    "destruction": frozenset(),
    "exploit": frozenset(),
    "discovery": frozenset(),
}

#: Behaviour reported by the off-host worker arrives as ``native.*`` /
#: ``dynamic.*`` ids. That tier observed the sample RUNNING, so its evidence is
#: authoritative; it is matched on the id's final segment against whole tokens.
_DYNAMIC_PREFIXES = ("native.", "dynamic.", "cuckoo.", "capev2.", "qiling.", "firejail.")
_DYNAMIC_TOKENS: dict[str, tuple[str, ...]] = {
    "execution": ("exec", "spawns_shell", "process_create", "run"),
    "network": ("network", "beacon", "c2", "connect", "dns", "http", "exfil"),
    # "infostealer" is the same whole-token miss as the destruction set: WannaCry
    # emitted `infostealer_browser` and `infostealer_cookies`, neither of which
    # matches "steal", so the rating came back C:N — no confidentiality impact —
    # for a sample observed reading browser credential stores.
    "credential": (
        "credential",
        "infostealer",
        "keylog",
        "clipboard",
        "browser_data",
        "steal",
    ),
    "persistence": ("persistence", "autostart", "registry_run", "schtask", "cron", "service_install"),
    "evasion": ("anti_debug", "anti_vm", "sandbox_evasion", "unhook", "tamper", "disable_defender"),
    "injection": ("injection", "hollow", "shellcode", "reflective", "wx_memory"),
    # Matching is whole-token, and this set missed almost everything a real
    # ransomware detonation emits. Measured on WannaCry
    # (ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa) through
    # CAPEv2 on our own sandbox: `ransomware_file_modifications` did not match
    # "ransom", `mass_data_encryption` did not match "encrypt_files", and
    # `deletes_shadow_copies` did not match "delete_shadow". Only
    # `mass_ransom_note_drop` matched — so the most recognisable ransomware in
    # existence earned its destruction capability on a single lucky hit, and a
    # variant that skipped the ransom note would have scored none at all.
    #
    # The keys below are written against the vocabulary a sandbox actually uses.
    # Multi-token keys keep it specific: "encryption" alone would fire on any
    # program that calls a crypto API; "mass" plus "encryption" would not.
    "destruction": (
        "ransom",
        "ransomware",
        "encrypt_files",
        "mass_encryption",
        "mass_data_encryption",
        "shadow_copies",
        "delete_shadow",
        "deletes_shadow",
        "system_state_backup",
        "wiper",
        "overwrite",
    ),
    "exploit": ("exploit", "heap_spray", "rop_chain"),
    "privilege": ("privilege", "uac_bypass", "getsystem", "token_theft"),
    "discovery": ("discovery", "enumerate", "systeminfo", "recon"),
    "dropper": ("dropped_file", "drops"),
}

CAPABILITY_LABELS: dict[str, str] = {
    "execution": "Code execution",
    "network": "Network / C2 communication",
    "credential": "Credential & data access",
    "persistence": "Persistence",
    "evasion": "Defence evasion",
    "injection": "Code injection / dynamic loading",
    "dropper": "Carries an executable payload",
    "privilege": "Privilege / elevation abuse",
    "deception": "Disguise / misrepresentation",
    "destruction": "Destructive / ransomware",
    "exploit": "Exploitation",
    "discovery": "Discovery / reconnaissance",
}

#: The sandbox's OWN classification of a behavioural signature, mapped to our
#: capability vocabulary.
#:
#: This exists because inferring a capability from a signature *name* does not
#: work, and cannot be made to work by adding keys. Measured on a real WannaCry
#: detonation: 8 of its 22 high-severity signals matched no key at all, because a
#: sandbox writes `unbacked_process_creation` where a developer writes
#: `process_create`, and `antivm_checks_available_memory` where a developer
#: writes `anti_vm`. Every one of those signatures carries a `categories` field
#: saying "execution", "evasion" and so on — an authoritative answer we were
#: throwing away in favour of guessing.
#:
#: Only categories that genuinely imply a capability are mapped. "generic",
#: "static", "malware", "ipc", "command" and the lateral-movement categories are
#: deliberately absent: either they say nothing specific, or they describe
#: something our capability set does not model, and inventing a mapping would
#: put a claim in a report that the evidence does not support.
SANDBOX_CATEGORY_CAPABILITIES: dict[str, str] = {
    # Destruction
    "ransomware": "destruction",
    "wiper": "destruction",
    # Credential and data access
    "infostealer": "credential",
    "credential_access": "credential",
    "memory scraping": "credential",
    "keylogger": "credential",
    # Network / C2
    "c2": "network",
    "network": "network",
    "exfiltration": "network",
    # Persistence
    "persistence": "persistence",
    "bootkit": "persistence",
    # Defence evasion
    "evasion": "evasion",
    "stealth": "evasion",
    "antivm": "evasion",
    "anti-vm": "evasion",
    "anti-debug": "evasion",
    "anti-sandbox": "evasion",
    "anti_sandbox": "evasion",
    "anti-analysis": "evasion",
    "obfuscation": "evasion",
    "packer": "evasion",
    "geofence": "evasion",
    # Injection / in-memory execution
    "injection": "injection",
    "shellcode": "injection",
    "fileless": "injection",
    # Execution. "command" is included because that is what the category means —
    # a signature about running commands (script_tool_executed,
    # suspicious_command_tools). It is also the least alarming capability we
    # model: anything that runs at all has it, so a generous reading here cannot
    # inflate a verdict on its own.
    "execution": "execution",
    "command": "execution",
    "script": "execution",
    # Discovery
    "discovery": "discovery",
    "recon": "discovery",
    "system_discovery": "discovery",
    "location_discovery": "discovery",
    # Privilege
    "privilege_escalation": "privilege",
    # Payload delivery
    "dropper": "dropper",
    "downloader": "dropper",
    # Exploitation
    "exploit": "exploit",
}


#: Capabilities whose presence in a report is an accusation, not an observation.
#: Claiming a sample destroys data, steals credentials, exploits a vulnerability
#: or injects code into another process changes what an analyst does next, so
#: these are held to a higher standard than "the sandbox filed this signature
#: under that heading".
#:
#: Injection is here on measurement, not principle. Across three signed
#: installers detonated on our own host, the only injection-category signature
#: any of them produced was `reads_memory_remote_process` at severity 2 — while
#: every malware sample that unpacked produced 2 to 20 of them at severity 3.
#: Ungated, that one medium signature was enough to call the 7-Zip installer
#: malicious.
HIGH_CONSEQUENCE = frozenset({"destruction", "credential", "exploit", "injection"})


def _load_shared_behaviours() -> frozenset[str]:
    """Signatures ordinary software also trips, so they cannot alone accuse it.

    A sandbox categorises a signature by the threat class it helps *detect*, not
    by what it proves. `mountpoint_manager_access` is filed under `ransomware`
    because ransomware enumerates volumes — but so does every installer. Measured
    on this deployment before the list existed: the 7-Zip installer scored CIR
    8.3 with a destruction capability, identical to WannaCry, on five such
    signatures alone.
    """
    path = Path(__file__).with_name("data_shared_behaviours.txt")
    if not path.is_file():  # pragma: no cover - the file ships with the package
        return frozenset()
    names = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        name = line.split("#", 1)[0].strip()
        if name:
            names.add(name)
    return frozenset(names)


SHARED_BEHAVIOURS: frozenset[str] = _load_shared_behaviours()


def _categories_of(signal: Signal) -> tuple[str, ...]:
    """The sandbox's categories for this signal, if it reported any."""
    evidence = getattr(signal, "evidence", None) or {}
    cats = evidence.get("categories") if isinstance(evidence, dict) else None
    if isinstance(cats, str):
        return (cats,)
    if isinstance(cats, (list, tuple)):
        return tuple(str(c) for c in cats)
    return ()


def _is_conclusive(signal: Signal) -> bool:
    """May this signal alone support a high-consequence claim?

    Two conditions, both measured rather than assumed: the sandbox rated it
    high, and it is not a behaviour ordinary software performs. Severity alone
    is not enough — `mass_file_modification_access` is severity 3 and an
    installer does it.
    """
    if SEVERITY_ORDER.get(signal.severity, 0) < SEVERITY_ORDER["high"]:
        return False
    tail = signal.id.split(".", 1)[1] if "." in signal.id else signal.id
    return tail not in SHARED_BEHAVIOURS


#: Reverse index, built once: signal id -> the capabilities it demonstrates.
_BY_SIGNAL: dict[str, tuple[str, ...]] = {}
for _cap, _ids in CAPABILITY_SIGNALS.items():
    for _sid in _ids:
        _BY_SIGNAL[_sid] = (*_BY_SIGNAL.get(_sid, ()), _cap)


def _dynamic_capabilities(signal_id: str) -> tuple[str, ...]:
    """Capabilities for a behaviour signal produced by the dynamic tier."""
    tail = signal_id.split(".", 1)[1] if "." in signal_id else signal_id
    tokens = set(tail.split("_"))
    found: list[str] = []
    for cap, keys in _DYNAMIC_TOKENS.items():
        for key in keys:
            # Whole-token match, or the multi-word key appearing as a run of
            # tokens — never a bare substring of a longer word.
            parts = key.split("_")
            if all(p in tokens for p in parts):
                found.append(cap)
                break
    return tuple(found)


def detect(signals: Iterable[Signal], iocs: IOCs | None = None) -> set[str]:
    """The capabilities the evidence actually demonstrates.

    ``iocs`` is accepted for call-site compatibility and deliberately unused:
    the mere presence of an indicator is not a capability. A README containing
    one URL used to be classified as a downloader because of it.
    """
    caps: set[str] = set()
    for signal in signals:
        if SEVERITY_ORDER.get(signal.severity, 0) < _MIN_SEVERITY:
            continue
        sid = signal.id
        if sid in _BY_SIGNAL:
            caps.update(_BY_SIGNAL[sid])
            continue
        if not sid.startswith(_DYNAMIC_PREFIXES):
            continue
        # Prefer the sandbox's own classification when it gave one: it is
        # authoritative about a signature it wrote, where reading the name is
        # inference. The token pass still runs, because engines that report no
        # categories (our native jail, Qiling) rely on it, and because a
        # category and a name can each catch what the other misses.
        conclusive = _is_conclusive(signal)
        for category in _categories_of(signal):
            cap = SANDBOX_CATEGORY_CAPABILITIES.get(category.strip().lower())
            if not cap:
                continue
            # Discovery, evasion, execution and friends cost little to be
            # generous about — every running program has them, and an analyst
            # reading "performs discovery" is not misled. Destruction,
            # credential theft and exploitation are accusations, and need a
            # signal the sandbox rated high which ordinary software does not
            # also trip.
            if cap in HIGH_CONSEQUENCE and not conclusive:
                continue
            caps.add(cap)
        caps.update(_dynamic_capabilities(sid))
    return caps


def describe(caps: Iterable[str]) -> list[str]:
    """Human-readable capability names, for the report and the UI."""
    return [CAPABILITY_LABELS.get(c, c) for c in sorted(caps)]
