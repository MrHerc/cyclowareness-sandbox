"""The evidentiary gate on accusing capabilities, and the ways it was bypassed.

`capabilities.detect` refuses to claim destruction, credential theft,
exploitation or injection unless the sandbox rated the signal high AND ordinary
software does not trip it. The corpus test proves that holds for eleven real
samples; this file proves it holds for the shapes the corpus happens not to
contain.

That distinction is the point. The gate shipped with a hole in it — the older
signal-name token pass ran unconditionally right after the category branch and
re-granted whatever the gate had just refused — and
`test_detonation_corpus.py` passed anyway, because no benign sample in it
carried a token-matching name. The corpus said "correct"; it meant "lucky".
"""
from __future__ import annotations

import pytest

from app.api.dynamic import _safe_suffix
from app.engine import capabilities, verdict
from app.engine.contracts import Signal


def _sig(sid: str, severity: str, categories: list[str] | None = None) -> Signal:
    return Signal(
        id=sid, title=sid, severity=severity, detail="",
        evidence={"categories": categories or []},
    )


# --- the gate itself ---------------------------------------------------------


@pytest.mark.parametrize(
    "sid,categories,capability",
    [
        # Reached through the sandbox's categories.
        ("capev2.some_encryption_thing", ["ransomware"], "destruction"),
        ("capev2.some_cred_thing", ["credential_access"], "credential"),
        ("capev2.some_inject_thing", ["injection"], "injection"),
        ("capev2.some_exploit_thing", ["exploit"], "exploit"),
        # Reached through the signal-name token pass. These are the ones that
        # leaked: `injection_rwx` at medium granted injection, and
        # `credential_dumping_lsass` granted credential, both after the
        # category branch had refused them.
        ("capev2.injection_rwx", [], "injection"),
        ("capev2.credential_dumping_lsass", [], "credential"),
        ("capev2.ransomware_note_dropped", [], "destruction"),
    ],
)
def test_an_accusation_needs_a_high_severity_signal(sid, categories, capability) -> None:
    below = capabilities.detect([_sig(sid, "medium", categories)])
    assert capability not in below, f"{sid} at medium granted {capability}"
    at_high = capabilities.detect([_sig(sid, "high", categories)])
    assert capability in at_high, f"{sid} at high should still grant {capability}"


@pytest.mark.parametrize("shared", sorted(capabilities.SHARED_BEHAVIOURS))
def test_no_shared_behaviour_can_accuse_even_at_high_severity(shared: str) -> None:
    """These are signatures ordinary software trips; severity does not redeem them."""
    got = capabilities.detect([_sig(f"capev2.{shared}", "high", ["ransomware", "wiper"])])
    assert not (got & capabilities.HIGH_CONSEQUENCE), f"{shared} accused of {sorted(got)}"


def test_low_consequence_capabilities_stay_generous() -> None:
    """Discovery and friends are descriptions, not accusations — no gate."""
    got = capabilities.detect([_sig("capev2.queries_something", "low", ["discovery"])])
    assert "discovery" in got


def test_the_detection_threshold_cannot_drift_from_the_evidence_threshold() -> None:
    """Two lists would let a sample be *detected* on evidence too weak to *claim*."""
    assert verdict.ACCUSING_CAPABILITIES is capabilities.HIGH_CONSEQUENCE


# --- every engine that reports behaviour must be understood ------------------


@pytest.mark.parametrize(
    "prefix", ["native.", "dynamic.", "cuckoo.", "capev2.", "qiling.", "firejail.", "joe."]
)
def test_every_dynamic_engine_prefix_is_recognised(prefix: str) -> None:
    """A prefix missing here silently yields no capability at all.

    `joe.` was absent. Because "malicious" additionally requires a nameable
    capability, a deployment whose only dynamic engine was Joe Sandbox could
    never reach a malicious verdict — every sample came back suspicious and
    named `Win32.Clean`.
    """
    got = capabilities.detect([_sig(f"{prefix}mass_data_encryption", "high", ["ransomware"])])
    assert "destruction" in got, f"{prefix} produces no capabilities"


def test_static_analyzer_ids_are_not_swept_up_by_the_dynamic_pass() -> None:
    """Static evidence goes through the exact-id table, not token matching."""
    assert capabilities.detect([_sig("pe.imports.crypto", "high", [])]) == set()


# --- the file name handed to the sandbox -------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("invoice.ps1", ".ps1"),
        ("SETUP.EXE", ".exe"),
        ("archive.tar.gz", ".gz"),
        ("noextension", ""),
        ("trailing.", ""),
        ("", ""),
        (None, ""),
        # `$` in Python also matches just before a trailing newline, and the
        # sanitiser used .match rather than .fullmatch — so this returned
        # ".exe\n", a newline in a value that builds a Content-Disposition
        # header and a file name on the worker's disk.
        ("invoice.exe\n", ""),
        ("invoice.exe\r\n", ""),
        ("invoice.exe\n\n", ""),
        ("a.ps1\r", ""),
        ("../../etc/passwd", ""),
        ("a.p s1", ""),
        ("a.ps1%00", ""),
        ("a.рs1", ""),
        ("a." + "z" * 20, ""),
    ],
)
def test_only_a_plain_extension_survives_sanitising(name, expected) -> None:
    assert _safe_suffix(name) == expected


def test_a_sanitised_suffix_is_always_header_safe() -> None:
    """It ends up in Content-Disposition; nothing that can break a header may pass."""
    hostile = [
        "x.exe\n", "x.exe\r", 'x.exe"', "x.exe;", "x.exe\t", "x.exe ", "x.e xe",
        "x.exe\x00", "x.exe ",
    ]
    for name in hostile:
        got = _safe_suffix(name)
        assert not (set(got) - set("abcdefghijklmnopqrstuvwxyz0123456789.")), (
            f"{name!r} produced {got!r}"
        )
