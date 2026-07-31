r"""Two wrong accusations, both found by putting a harmless file through the product.

I submitted a .bat that runs `whoami`, `ipconfig`, `reg query ...\Run` and
`ping example.com` to the live deployment. The pipeline worked end to end —
static, a real 250-second detonation, nine behavioural signals, re-score — and
called it

    Batch.Downloader.Persistence      impact 7.5 high

It downloads nothing and it persists nothing.

Both causes are the same mistake in different places: **examining a thing is not
using it.**
"""
from __future__ import annotations

import pytest

from app.engine.capabilities import _dynamic_capabilities, detect
from app.engine.contracts import Signal


def _sig(sid: str, severity: str = "high") -> Signal:
    return Signal(id=sid, title=sid, severity=severity, detail="", evidence={})


# --- 1. an anti-analysis check is evasion, whatever it inspected -------------


def test_an_antivm_adapter_check_is_not_network_capability() -> None:
    """The finding. CAPE's signal is "checks adapter addresses which can be used
    to detect a virtual network interface" — it ENUMERATES adapters, it does not
    communicate, and granting `network` is what produced `Downloader`."""
    caps = _dynamic_capabilities("capev2.antivm_network_adapters")
    assert "network" not in caps, caps
    assert caps == ("evasion",)


@pytest.mark.parametrize("sid", [
    "capev2.antivm_network_adapters",
    "capev2.antivm_generic_disk",
    "capev2.antidebug_setunhandledexceptionfilter",
    "capev2.antisandbox_sleep",
    "capev2.antianalysis_tls_section",
    "capev2.antiemulation_cpu_probe",
])
def test_every_anti_marker_yields_evasion_only(sid) -> None:
    """The rest of the name is the SUBJECT of the check, never a capability."""
    assert _dynamic_capabilities(sid) == ("evasion",)


def test_stealth_is_deliberately_not_an_anti_marker() -> None:
    """`stealth_network_connection` really is a connection, made quietly. The
    anti-* family is about LOOKING, and that is the whole distinction."""
    assert "network" in _dynamic_capabilities("capev2.stealth_network_connection")


@pytest.mark.parametrize("sid,cap", [
    ("capev2.network_http_request", "network"),
    ("capev2.persistence_autorun", "persistence"),
    ("capev2.injection_createremotethread", "injection"),
])
def test_ordinary_signals_still_grant_their_capability(sid, cap) -> None:
    """The rule must not have made the token pass useless."""
    assert cap in _dynamic_capabilities(sid)


def test_the_probe_sample_is_no_longer_a_downloader() -> None:
    """The nine signals the live detonation actually produced."""
    observed = [
        "capev2.queries_locale_api",
        "capev2.antidebug_setunhandledexceptionfilter",
        "capev2.antivm_network_adapters",
        "capev2.stealth_timeout",
        "capev2.language_check_registry",
        "capev2.privilege_elevation_check",
        "capev2.suspicious_ping_use",
        "capev2.uses_windows_utilities",
        "capev2.hardware_id_profiling",
    ]
    caps = detect([_sig(s) for s in observed])
    assert "network" not in caps, caps


# --- 2. reading the Run key is discovery, not persistence --------------------


def _via_detectors(text: str) -> set[str]:
    """Signal ids the script analyzer raises for this source.

    Drives the detector table directly rather than the whole analyzer, so a
    failure names the rule rather than the pipeline around it.
    """
    from app.engine.analyzers import scripts

    out = set()
    for det in scripts._DETECTORS:
        if any(pattern.search(text) for _label, pattern in det.patterns):
            out.add(det.signal_id)
    return out


READS = [
    r'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"',
    r'reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Foo',
    r'Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"',
]

WRITES = [
    r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Evil /d payload.exe',
    r'New-ItemProperty -Path "HKCU:\...\CurrentVersion\Run" -Name Evil -Value x',
    r'Set-ItemProperty -Path HKCU:\...\Run -Name Evil -Value x',
    r'schtasks /create /tn Evil /tr payload.exe',
    r'reg import evil.reg',
]


@pytest.mark.parametrize("source", READS)
def test_reading_the_run_key_is_not_persistence(source) -> None:
    """`reg query` READS. The same string appears whether it is read or written,
    and the bare key pattern could not tell — measured on a .bat that only
    queried it and was accused of `Batch.Downloader.Persistence`."""
    assert "script.persistence" not in _via_detectors(source), source


@pytest.mark.parametrize("source", WRITES)
def test_writing_it_still_is(source) -> None:
    """The detection this rule exists for must survive."""
    assert "script.persistence" in _via_detectors(source), source


# --- and the ATT&CK panel, which had the same mistake ------------------------


def _tech(sid):
    from app.engine.mitre import map_techniques
    return {t["technique_id"] for t in map_techniques([_sig(sid)])}


def test_an_antivm_check_is_evasion_in_the_attack_panel_too() -> None:
    """The capability model short-circuits an anti-* marker to evasion. The
    technique table had to as well, or the same report says no network
    capability and a Command-and-Control technique on one page."""
    assert _tech("capev2.antivm_network_adapters") == {"T1497"}
    assert _tech("capev2.antidebug_setunhandledexceptionfilter") == {"T1497"}


def test_a_real_network_signal_is_still_c2() -> None:
    assert "T1071" in _tech("capev2.network_http_request")


def test_a_windows_sample_is_not_filed_under_a_mobile_technique() -> None:
    """T1426 is System Information Discovery in ATT&CK for **Mobile**; the
    Enterprise technique of the same name is T1082.

    One rule mixed two Android APIs with three generic words, so every Windows
    and Linux discovery signal landed on the mobile ID. A report naming a real
    technique is making a checkable claim, and anyone who looked T1426 up found
    a mobile technique attached to a PE file.
    """
    assert _tech("capev2.systeminfo_enumeration") == {"T1082"}
    assert _tech("capev2.hardware_id_profiling") == {"T1082"}
    assert "T1426" not in _tech("capev2.discovery_process_list")


def test_an_android_signal_still_gets_the_mobile_technique() -> None:
    assert _tech("apk.getdeviceid") == {"T1426"}


def test_packing_is_mapped_at_all() -> None:
    """There was no rule for it, while  fires 41 times and
     34 times across the 88-sample fixture."""
    assert _tech("capev2.packer_entropy") == {"T1027.002"}
    assert _tech("pe.packer_upx") == {"T1027.002"}
