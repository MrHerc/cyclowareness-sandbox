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
    "credential": ("credential", "keylog", "clipboard", "browser_data", "steal"),
    "persistence": ("persistence", "autostart", "registry_run", "schtask", "cron", "service_install"),
    "evasion": ("anti_debug", "anti_vm", "sandbox_evasion", "unhook", "tamper", "disable_defender"),
    "injection": ("injection", "hollow", "shellcode", "reflective", "wx_memory"),
    "destruction": ("ransom", "encrypt_files", "wiper", "delete_shadow", "overwrite"),
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
        elif sid.startswith(_DYNAMIC_PREFIXES):
            caps.update(_dynamic_capabilities(sid))
    return caps


def describe(caps: Iterable[str]) -> list[str]:
    """Human-readable capability names, for the report and the UI."""
    return [CAPABILITY_LABELS.get(c, c) for c in sorted(caps)]
