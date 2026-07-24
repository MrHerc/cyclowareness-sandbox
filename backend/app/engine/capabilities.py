"""What a sample can *do*, distilled from the signals the analyzers fired.

One shared taxonomy so the CVSS mapping, the threat classification and the
MITRE ATT&CK mapping all reason about the same set of observed capabilities
rather than re-deriving them three different ways. A capability is only ever
asserted because a signal supports it — this is a summary of evidence, never a
guess.
"""
from __future__ import annotations

from typing import Iterable

from .contracts import IOCs, Signal

#: capability -> substrings that, seen in a signal id or title, assert it.
CAPABILITY_KEYS: dict[str, tuple[str, ...]] = {
    "network": ("download", "network", "beacon", "c2", "remote_url", "connect", "http", "exfil", "webclient", "url"),
    "credential": ("credential", "stealer", "steal", "password", "getdeviceid", "sendtextmessage",
                   "sms", "contacts", "keylog", "clipboard", "sim_serial", "record_audio", "browser_data"),
    "persistence": ("persistence", "autorun", "boot", "schtask", "registry_run", "cron", "systemd", "startup", "service_install"),
    "evasion": ("defense_evasion", "amsi", "disable", "anti_debug", "anti_vm", "obfuscat", "tamper", "unhook", "hidden_window"),
    "injection": ("dynamic_execution", "classloader", "dynamic_code", "injection", "reflective", "shellcode", "hollow", "encoded_command"),
    "destruction": ("ransom", "encrypt", "wiper", "wipe", "destroy", "delete_shadow", "overwrite"),
    "exploit": ("exploit", "launch_action", "cve", "openaction", "heap_spray", "rop", "embedded_executable"),
    "privilege": ("accessibility_abuse", "device_admin", "uac_bypass", "privilege", "getsystem", "token", "request_install"),
    "execution": ("download_and_execute", "runtime_exec", "process", "wscript", "powershell", "macro", "suspicious_api", "spawns_shell"),
    "discovery": ("getinstalledpackages", "enumerate", "recon", "systeminfo", "discovery"),
}

#: human-readable capability names for the UI / report.
CAPABILITY_LABELS: dict[str, str] = {
    "network": "Network / C2 communication",
    "credential": "Credential & data access",
    "persistence": "Persistence",
    "evasion": "Defence evasion",
    "injection": "Code injection / dynamic execution",
    "destruction": "Destructive / ransomware",
    "exploit": "Exploitation",
    "privilege": "Privilege / elevation abuse",
    "execution": "Code execution",
    "discovery": "Discovery / reconnaissance",
}


def detect(signals: Iterable[Signal], iocs: IOCs | None = None) -> set[str]:
    hay = " ".join(f"{s.id} {s.title}".lower() for s in signals)
    caps = {cap for cap, keys in CAPABILITY_KEYS.items() if any(k in hay for k in keys)}
    if iocs and (iocs.urls or iocs.ips or iocs.domains):
        caps.add("network")
    return caps
