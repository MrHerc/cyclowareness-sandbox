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
    (("getdeviceid", "getinstalledpackages", "systeminfo", "enumerate", "discovery"),
     "T1426", "System Information Discovery", "Discovery"),
    (("autorun.inf", "removable"),
     "T1091", "Replication Through Removable Media", "Lateral Movement"),
    (("ransom", "encrypt_files", "delete_shadow", "wiper"),
     "T1486", "Data Encrypted for Impact", "Impact"),
    (("embedded_executable", "dropped", "native_libs", "embedded_url"),
     "T1105", "Ingress Tool Transfer", "Command and Control"),
)


def map_techniques(signals: Iterable[Signal]) -> list[dict[str, Any]]:
    """Return the ATT&CK techniques the signals map to, with their evidence."""
    signals = list(signals)
    found: dict[str, dict[str, Any]] = {}
    for signal in signals:
        hay = f"{signal.id} {signal.title}".lower()
        for keys, tid, name, tactic in _RULES:
            if any(k in hay for k in keys):
                entry = found.setdefault(
                    tid, {"technique_id": tid, "name": name, "tactic": tactic, "evidence": []}
                )
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
