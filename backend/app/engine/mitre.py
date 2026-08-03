"""MITRE ATT&CK technique mapping.

Every signal the analyzers fire is checked against a curated table of ATT&CK
techniques (real technique IDs and tactics). The result is the set of techniques
the sample's observed behaviour maps to, each with the signals that evidenced it
— the same language a SOC analyst already uses to triage and report.

The mapping is intentionally conservative: a technique is only asserted when a
signal concretely supports it, and each mapped technique carries its evidence so
it can be checked.
"""
from __future__ import annotations

from typing import Any, Iterable

from .contracts import Signal

# (match substrings, technique_id, technique_name, tactic)
_RULES: tuple[tuple[tuple[str, ...], str, str, str], ...] = (
    (("download_and_execute", "download", "ingress", "webclient", "downloadfile"),
     "T1105", "Ingress Tool Transfer", "Command and Control"),
    # NOT a bare "remote". Matched as a substring it caught four
    # process-manipulation signals in the corpus —
    # `capev2.injection_createremotethread`, `reads_memory_remote_process`,
    # `resumethread_remote_process`, `terminates_remote_process` — and filed all
    # of them under Command and Control, which is where an analyst goes looking
    # for network activity. A report that puts process injection under C2 sends
    # the reader to the wrong place and is wrong about the technique.
    (("network", "beacon", "c2", "remote_template", "remote_host", "remote_url",
      "remote_content", "http_request", "connect"),
     "T1071", "Application Layer Protocol", "Command and Control"),
    (("powershell", "encoded_command", "amsi"),
     "T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"),
    (("jscript", "javascript", ".js", "wscript"),
     "T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution"),
    (("vbscript", "vbs", "createobject"),
     "T1059.005", "Command and Scripting Interpreter: Visual Basic", "Execution"),
    (("batch", "cmd_", "bat_"),
     "T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "Execution"),
    (("python", "shell_"),
     "T1059", "Command and Scripting Interpreter", "Execution"),
    (("runtime_exec", "process_builder", "spawns_shell", "suspicious_api"),
     "T1106", "Native API", "Execution"),
    (("macro", "autoexec", "autoopen", "auto_open"),
     "T1204.002", "User Execution: Malicious File", "Execution"),
    (("launch_action", "openaction", "exploit", "shellcode", "heap_spray"),
     "T1203", "Exploitation for Client Execution", "Execution"),
    (("obfuscat", "encoded", "base64", "packed", "high_entropy"),
     "T1027", "Obfuscated Files or Information", "Defense Evasion"),
    (("decoded_layer", "deobfuscat", "unescape"),
     "T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion"),
    (("defense_evasion", "disable", "tamper", "unhook", "set-mppreference", "disablerealtime"),
     "T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    (("anti_debug", "anti_vm", "sandbox_evasion", "hidden_window"),
     "T1497", "Virtualization/Sandbox Evasion", "Defense Evasion"),
    (("classloader", "reflection", "reflective", "dynamic_code", "defineclass"),
     "T1620", "Reflective Code Loading", "Defense Evasion"),
    # The remote-process tokens live here, where they belong: writing to,
    # reading from or resuming a thread in another process is the technique
    # itself. They were previously swept up by the bare "remote" above.
    (("injection", "hollow", "process_inject", "createremotethread",
      "remote_process", "remote_thread"),
     "T1055", "Process Injection", "Defense Evasion"),
    (("schtask", "scheduled_task"),
     "T1053.005", "Scheduled Task/Job: Scheduled Task", "Persistence"),
    (("registry_run", "run_key", "currentversion\\run"),
     "T1547.001", "Boot or Logon Autostart: Registry Run Keys", "Persistence"),
    (("cron",),
     "T1053.003", "Scheduled Task/Job: Cron", "Persistence"),
    (("systemd", "service_install"),
     "T1543.002", "Create or Modify System Process: systemd Service", "Persistence"),
    (("boot", "receive_boot_completed", "autorun_persist"),
     "T1547", "Boot or Logon Autostart Execution", "Persistence"),
    (("credential", "password", "browser_data", "stealer"),
     "T1555", "Credentials from Password Stores", "Credential Access"),
    (("keylog",),
     "T1056.001", "Input Capture: Keylogging", "Collection"),
    (("sms", "sendtextmessage", "read_sms"),
     "T1636.004", "Protected User Data: SMS Messages", "Collection"),
    (("record_audio",),
     "T1429", "Audio Capture", "Collection"),
    (("accessibility_abuse", "device_admin", "uac_bypass", "request_install"),
     "T1626", "Abuse Elevation Control Mechanism", "Privilege Escalation"),
    # SPLIT BY PLATFORM. This was one rule ending in `T1426`, which is System
    # Information Discovery in ATT&CK for **Mobile**; the Enterprise technique of
    # the same name is T1082. `getdeviceid` and `getinstalledpackages` are
    # Android APIs, so the rule was written for the APK analyzer — but
    # `systeminfo`, `enumerate` and `discovery` are generic, so every Windows and
    # Linux discovery signal was filed under a mobile ID. A report naming a real
    # technique is making a checkable claim, and anyone who looked T1426 up found
    # a mobile technique attached to a PE file.
    (("getdeviceid", "getinstalledpackages", "getsubscriberid", "getsimserial"),
     "T1426", "System Information Discovery (Mobile)", "Discovery"),
    (("systeminfo", "enumerate", "discovery", "reconnaissance", "hardware_id",
      "computer_name", "mount_points"),
     "T1082", "System Information Discovery", "Discovery"),
    # Packing had no rule at all, while `packer_entropy` fires 41 times and
    # `packer_unknown_pe_section_name` 34 times across the 88-sample fixture. It
    # is the one unambiguous entry among the 136 unmapped ids — the signal says
    # the file is packed, and that is the technique. The rest stay unmapped on
    # purpose; this module is conservative by design.
    (("packer", "upx", "themida", "vmprotect", "software_packing"),
     "T1027.002", "Obfuscated Files or Information: Software Packing", "Defense Evasion"),
    (("autorun.inf", "removable"),
     "T1091", "Replication Through Removable Media", "Lateral Movement"),
    (("ransom", "encrypt_files", "delete_shadow", "wiper"),
     "T1486", "Data Encrypted for Impact", "Impact"),
    (("embedded_executable", "dropped", "native_libs", "embedded_url"),
     "T1105", "Ingress Tool Transfer", "Command and Control"),
)


#: Signals whose NAME says they are an anti-analysis check. The rest of the name
#: is what the check LOOKED AT, not what the sample did with it.
#:
#: `capev2.antivm_network_adapters` contains the substring `network`, and the
#: T1071 key list contains `network`, so "checks adapter addresses to detect a
#: virtual network interface" was filed under **Command and Control** — the
#: tactic an analyst opens to find out who the sample talked to. The capability
#: model short-circuits the same marker to `evasion`; without this the report
#: contradicts itself on one page.
#:
#: T1497 is the honest answer and this table already carried it; the substring
#: pass simply matched first.
_ANTI_ANALYSIS = ("antivm", "antidebug", "antisandbox", "antianalysis",
                  "antiemulation", "antiav", "antidbg")
_ANTI_TECHNIQUE = ("T1497", "Virtualization/Sandbox Evasion", "Defense Evasion")


def _is_anti_analysis(signal: Signal) -> bool:
    """Does the signal ID declare itself an anti-analysis check?

    Read from the ID's own tokens, never from the title — a title is prose and
    routinely says "possible anti-debug" about something else entirely.
    """
    tail = signal.id.split(".", 1)[-1]
    return any(token in _ANTI_ANALYSIS for token in tail.split("_"))


def map_techniques(
    signals: Iterable[Signal],
    *,
    exclude: frozenset[str] | set[str] | None = None,
) -> list[dict[str, Any]]:
    """Return the ATT&CK techniques the signals map to, with their evidence.

    `exclude` drops signal ids that must not assert a technique. There is no
    severity gate here on purpose — a blanket one was measured and rejected,
    because it removed 362 techniques across the deployment including 28 on
    malicious samples — so an id that has been demoted for scoring still maps
    unless it is named here.

    That asymmetry produced a live wrong claim. `capev2.stealth_network` is a
    guaranteed false positive on Linux (the strace processor emits category
    `net`, the signature looks for `network`), and on the first real ELF
    detonation it asserted **T1071 Application Layer Protocol** on a report
    whose score had deliberately ignored it. A technique in an ATT&CK panel is
    an accusation with a reference number.
    """
    signals = list(signals)
    if exclude:
        signals = [s for s in signals if s.id not in exclude]
    found: dict[str, dict[str, Any]] = {}
    for signal in signals:
        if _is_anti_analysis(signal):
            tid, name, tactic = _ANTI_TECHNIQUE
            # `_is_anti_analysis` matches whole underscore/dot tokens of the ID
            # (mitre.py:136), never the prose, so this branch is id-backed by
            # construction. Stated rather than left absent, because a missing
            # `basis` on one branch is how a consumer learns to treat the field
            # as optional and then stops rendering it.
            entry = found.setdefault(
                tid,
                {
                    "technique_id": tid, "name": name, "tactic": tactic,
                    "evidence": [], "basis": "signal-id",
                },
            )
            entry["basis"] = "signal-id"
            if signal.id not in entry["evidence"]:
                entry["evidence"].append(signal.id)
            continue
        # WHAT THE MATCH RESTED ON IS PART OF THE CLAIM.
        #
        # The rule table is matched against the signal id AND its prose title,
        # and the title is where a sandbox writes its hypotheses. Measured over
        # 751 stored jobs: 1,012 of 4,551 technique assertions (22%) rest on the
        # description alone, and the descriptions doing it hedge --
        #
        #   "Queried the FIPS cryptography policy, can be used to adapt C2
        #    network behaviour"                                    -> T1071
        #   "Queries registry mount points to identify historical or connected
        #    removable drives"                                     -> T1091
        #   "Performs high-volume NtQueryInformationToken calls"   -> T1486
        #
        # -- the last one on PsInfo64.exe, which the engine calls clean.
        #
        # TWO REPAIRS WERE MEASURED AND BOTH WERE WORSE THAN THE DISEASE.
        # Matching ids only costs 897-1,105 techniques on MALICIOUS samples;
        # ignoring hedged titles costs 603. The bar this codebase already set is
        # 28 (mitre.py:148, and the severity gate rejected at that price). The
        # mapping's coverage genuinely rests on prose, so deleting prose deletes
        # the mapping.
        #
        # So the claim is kept and its FOOTING is published. `basis` is
        # "signal-id" when the identifier itself carries the keyword -- a
        # structured, stable fact -- and "description" when only the sandbox's
        # sentence did. A reader can then weigh a technique instead of being
        # asked to trust it, which is the same move this product makes wherever
        # it cannot measure something: state the limit rather than hide it.
        low_id = signal.id.lower()
        low_title = str(signal.title or "").lower()
        for keys, tid, name, tactic in _RULES:
            in_id = any(k in low_id for k in keys)
            in_title = any(k in low_title for k in keys)
            if not (in_id or in_title):
                continue
            entry = found.setdefault(
                tid,
                {
                    "technique_id": tid,
                    "name": name,
                    "tactic": tactic,
                    "evidence": [],
                    "basis": "description",
                },
            )
            # One id-backed signal is enough to make the whole technique
            # id-backed: the strongest available footing wins, and it is a
            # property of the claim, not of the last signal that touched it.
            if in_id:
                entry["basis"] = "signal-id"
            if signal.id not in entry["evidence"]:
                entry["evidence"].append(signal.id)
    # Stable order: by tactic then technique id.
    _TACTIC_ORDER = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact",
    ]
    return sorted(
        found.values(),
        key=lambda t: (_TACTIC_ORDER.index(t["tactic"]) if t["tactic"] in _TACTIC_ORDER else 99, t["technique_id"]),
    )
