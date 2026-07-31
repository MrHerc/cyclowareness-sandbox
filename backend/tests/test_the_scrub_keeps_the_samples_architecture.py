"""The scrub that hides the detonation host also deleted the sample's architecture.

`_INFRASTRUCTURE_KEYS` contained `"machine"`, and `_without_infrastructure`
removes a listed key from EVERY dict anywhere in the payload. But `machine` is
what `pe.py` and `elf.py` call the sample's TARGET ARCHITECTURE -- AMD64,
x86-64, ARM64 -- so a fact about the SAMPLE was deleted from `export.json` and
from the signed evidence because it shares a name with a fact about the
infrastructure.

Architecture is not incidental here. ARM64 is why CAPE had no matching guest for
eleven samples, and it is the first thing an analyst checks when a detonation
produced nothing.

The word means two things and the fix has to know which: in `dynamic.*` and in
the tiers it is which of OUR guests ran the sample, and it still goes; in `pe`
and `elf` it is the binary's own header field, and it stays.

`test_no_export_names_the_machine_that_ran_it` caught the first attempt at this,
which scrubbed the tiers and forgot that the dynamic ANALYZER carries the guest
name too. That test is the other half of this one and both must pass.
"""
from __future__ import annotations

from app.engine import report as report_mod


class _Job:
    """Enough of a job for the export path, carrying both meanings of `machine`."""

    public_id = "11111111-1111-4111-8111-111111111111"
    original_name = "sample.exe"
    sha256 = "a" * 64
    md5 = "b" * 32
    size_bytes = 4096
    mime = "application/x-dosexec"
    magic = "PE32+ executable"
    family = "pe"
    status = "completed"
    risk_level = "high"
    final_score = 71.0
    rule_score = 70.0
    ai_score = 72.0
    extension_mismatch = 0
    source = "upload"
    verdict = {"verdict": "malicious", "threat_name": "Win32.Trojan.X",
               "detection_ratio": "1 / 7", "engines": []}
    impact = {"base_score": 7.1, "severity": "high", "capabilities": []}
    mitre: list = []
    iocs: dict = {}
    score_breakdown: dict = {}
    analysis = {
        # The sample's own header field.
        "pe": {"ran": True, "signals": [], "facts": {"machine": "AMD64"}, "iocs": {}},
        # One of OUR guests.
        "dynamic.capev2": {
            "ran": True, "signals": [], "iocs": {},
            "facts": {"machine": "cape1", "engine": "capev2", "worker": "cyclo-worker"},
        },
    }
    tiers = {
        "static": {"ran": True},
        "dynamic": {"ran": True, "engine": "capev2", "machine": "cape1",
                    "worker": "cyclo-worker"},
    }
    dynamic = {"ran": True, "machine": "cape1", "worker": "cyclo-worker"}


def test_the_architecture_survives() -> None:
    """A fact about the sample, in the evidence, where an analyst needs it."""
    exported = report_mod.as_json(_Job())
    assert exported["analyzers"]["pe"]["facts"]["machine"] == "AMD64"


def test_the_guest_name_does_not() -> None:
    """The other half. Both, or neither is worth anything."""
    body = str(report_mod.as_json(_Job())).lower()
    assert "cape1" not in body
    assert "cyclo-worker" not in body


def test_the_dynamic_analyzer_is_scrubbed_too() -> None:
    """The first attempt scrubbed the tiers and forgot the analyzer beside them."""
    facts = report_mod.as_json(_Job())["analyzers"]["dynamic.capev2"]["facts"]
    assert "machine" not in facts
    assert facts.get("engine") == "capev2", "the engine name is not infrastructure"


def test_the_tiers_are_scrubbed() -> None:
    tiers = report_mod.as_json(_Job())["tiers"]
    assert "machine" not in tiers.get("dynamic", {})
    assert tiers.get("dynamic", {}).get("engine") == "capev2"


def test_machine_is_not_in_the_blanket_list() -> None:
    """Stated directly: putting it back reintroduces the defect everywhere."""
    assert "machine" not in report_mod._INFRASTRUCTURE_KEYS
    assert "machine" in report_mod._DYNAMIC_ONLY_KEYS
