"""A detonation that cannot be attributed may not accuse — in ANY consumer.

There are two unrelated reasons the dynamic tier is shown and may not be
concluded from, and until now the guard was built for one of them:

  calibration      nobody measured this platform's signatures against benign
                   software (`elf`). Covered by
                   test_a_trace_is_a_document_until_it_is_calibrated.py.
  attributability  Windows cannot execute this file at all, so whatever the
                   guest did, the sample did not do it. 226 inert files —
                   READMEs, LICENSEs, man pages, CA bundles — were detonated
                   before `_needs_dynamic` stopped offering them, and their
                   reports are carried forward deliberately.

`scoring.assess` has honoured the second since those 226 were found: measured
on the live image, a `script` with three `capev2` signals scores `rule=7.0`
not-attributable against `98.0` attributable. Every other consumer took the
first axis and stopped, so the same trace the score refused to count still
reached the verdict:

    README.html, three capev2 signals + capev2.detection.ryuk
    -> verdict MALICIOUS, Script.Malware.Ryuk, SandboxID detected=True
       severity=critical, at a final_score of 5.9

A man page came out `T1055 Process Injection` the same way. The score breakdown
says "Windows has no way to run a file of this type… excluded from the score"
three keys away from the verdict built out of it.

WHY THE EXISTING SYMMETRY TEST COULD NOT SEE IT.
`test_a_second_path_forgot_the_rule` asserts the pipeline and the report handler
hand `impact.assess` and `verdict.classify` the same arguments. They did. Both
were equally wrong, and two paths agreeing on a mistake is what a symmetry test
is blind to by construction.
"""
from __future__ import annotations

import pytest

from app.engine import impact, scoring, verdict
from app.engine.capabilities import detect as detect_capabilities
from app.engine.contracts import AnalyzerResult, IOCs, Signal

DETONATION = [
    Signal(id="capev2.ransomware_file_modifications", title="Mass file writes",
           severity="high", detail="", evidence={}),
    Signal(id="capev2.injects_code", title="Injects into a process",
           severity="high", detail="", evidence={}),
    Signal(id="capev2.deletes_files", title="Deletes files",
           severity="high", detail="", evidence={}),
]
#: What CAPE emits when it names a family. This is the one that set the verdict.
IDENTIFIED = Signal(id="capev2.detection.ryuk", title="CAPE identified Ryuk",
                    severity="critical", detail="", evidence={"family": "Ryuk"})
ALL = DETONATION + [IDENTIFIED]


def _results(iocs: IOCs | None = None) -> list[AnalyzerResult]:
    return [AnalyzerResult(analyzer="dynamic.capev2", ran=True, signals=list(ALL),
                           iocs=iocs or IOCs())]


def test_the_score_already_refused_it() -> None:
    """The half that was right, kept as the reference for the other consumers."""
    no = scoring.assess(_results(), ioc_total=0, family="script", dynamic_attributable=False)
    yes = scoring.assess(_results(), ioc_total=0, family="script", dynamic_attributable=True)
    assert no.rule_score < yes.rule_score / 5, (no.rule_score, yes.rule_score)


def test_an_unattributable_detonation_names_no_family_and_no_verdict() -> None:
    result = verdict.classify("script", "text/html", _results(), IOCs(), 5.9,
                              attributable=False)
    sandbox_id = next(r for r in result.engines if r["engine"] == "CS-SandboxID")
    assert sandbox_id["detected"] is False, sandbox_id
    assert "Ryuk" not in result.threat_name, result.threat_name
    assert result.verdict != "malicious", result.verdict


def test_the_same_evidence_still_accuses_when_it_IS_attributable() -> None:
    """This is a statement about files Windows cannot run, not a way to silence
    CAPE. A `.js` with the identical trace is still Ryuk."""
    result = verdict.classify("script", "text/javascript", _results(), IOCs(), 5.9,
                              attributable=True)
    sandbox_id = next(r for r in result.engines if r["engine"] == "CS-SandboxID")
    assert sandbox_id["detected"] is True, sandbox_id
    assert result.verdict == "malicious", result.verdict
    assert "Ryuk" in result.threat_name, result.threat_name


#: The dynamic half of a REAL stored report: rclone's `README.html`, job
#: c01ad0d2 on the live deployment, which was rated `8.2 / high` and given eight
#: ATT&CK techniques. Taken from the database rather than invented, because a
#: three-signal fixture does NOT reproduce this — `detect_capabilities` requires
#: corroboration, and a real detonation supplies it by volume where a synthetic
#: one does not. My first version of this test asserted the leak with three
#: signals, measured 0.0 on both axes, and would have been written off as a
#: false alarm.
#:
#: All 39 of them. A truncated fixture is why the first two versions of this
#: test failed: `capev2.antisandbox_unhook` is the signal the threat name is
#: built from, and it was not in the first 14 ids I copied out of the row.
README_HTML = [
    Signal(id=i, title="", severity=sev, detail="", evidence={})
    for i, sev in [
        ("capev2.antivm_checks_available_memory", "low"),
        ("capev2.queries_computer_name", "low"),
        ("capev2.dead_connect", "low"),
        ("capev2.queries_keyboard_layout", "low"),
        ("capev2.queries_locale_api", "low"),
        ("capev2.suspicious_html_title", "low"),
        ("capev2.accesses_public_folder", "low"),
        ("capev2.antidebug_setunhandledexceptionfilter", "low"),
        ("capev2.antivm_network_adapters", "low"),
        ("capev2.stealth_timeout", "low"),
        ("capev2.language_check_registry", "low"),
        ("capev2.anomalous_deletefile", "medium"),
        ("capev2.mouse_movement_detect", "medium"),
        ("capev2.antisandbox_system_parameters_info", "medium"),
        ("capev2.privilege_elevation_check", "medium"),
        ("capev2.query_fips_reconnaissance", "medium"),
        ("capev2.mountpoints_volume_discovery", "medium"),
        ("capev2.registers_vectored_exception_handler", "medium"),
        ("capev2.per_file_acl_token_check", "medium"),
        ("capev2.creates_suspended_process", "medium"),
        ("capev2.resumethread_remote_process", "medium"),
        ("capev2.injection_write_process", "medium"),
        ("capev2.reads_memory_remote_process", "medium"),
        ("capev2.createtoolhelp32snapshot_module_enumeration", "medium"),
        ("capev2.terminates_remote_process", "medium"),
        ("capev2.discover_registry_mount_points", "medium"),
        ("capev2.antisandbox_unhook", "high"),
        ("capev2.hardware_id_profiling", "high"),
        ("capev2.antivm_display", "high"),
        ("capev2.antivm_generic_system", "high"),
        ("capev2.physical_drive_access", "high"),
        ("capev2.suspicious_iocontrol_codes", "high"),
        ("capev2.mountpoint_manager_access", "high"),
        ("capev2.interprocess_comms_shared_memory", "high"),
        # An HTML readme, reported as modifying files the way ransomware does.
        ("capev2.ransomware_file_modifications", "high"),
        ("capev2.recon_programs", "high"),
        ("capev2.binary_yara", "high"),
        ("capev2.folder_enumeration", "high"),
        ("capev2.suspicious_command_tools", "high"),
    ]
]
#: The static half, which is the sample's own and must survive untouched. All
#: six, for the same reason the dynamic list is complete: with three of them the
#: guarded verdict came out `clean` rather than `suspicious`, and the test would
#: have asserted a stronger claim than the change actually makes.
README_STATIC = [
    Signal(id=i, title="", severity=sev, detail="", evidence={})
    for i, sev in [
        ("document.mentions_remote_payload", "low"),
        ("document.mentions_dynamic_execution", "low"),
        ("document.mentions_persistence", "low"),
        ("script.long_one_liner", "medium"),
        ("generic.many_urls", "low"),
        ("generic.suspicious_tld", "low"),
    ]
]


def test_the_threat_name_is_not_built_from_the_guest() -> None:
    """The live effect of this change, measured on job c01ad0d2's real signals.

        attributable=True    Script.Downloader.AntisandboxUnhook
        attributable=False   Script.Suspicious.LongOneLiner

    `AntisandboxUnhook` is the guest noticing it is being watched. It was the
    headline on an HTML readme. The name now comes from `script.long_one_liner`
    — the sample's own static finding — which is both true and useful.
    """
    signals = README_STATIC + README_HTML
    results = [AnalyzerResult(analyzer="dynamic.capev2", ran=True, signals=signals)]
    charged = verdict.classify("script", "text/html", results, IOCs(), 15.0, attributable=True)
    guarded = verdict.classify("script", "text/html", results, IOCs(), 15.0, attributable=False)
    assert "Antisandbox" in charged.threat_name, charged.threat_name
    assert "Antisandbox" not in guarded.threat_name, guarded.threat_name
    #: Still suspicious, and correctly so — 15.0 is the STATIC score of a file
    #: with a long one-liner and a suspicious TLD in it. The guard removes the
    #: guest's contribution, not the sample's.
    assert guarded.verdict == "suspicious", guarded.verdict


def test_the_impact_rating_is_not_built_from_the_guest() -> None:
    """The rating travels inside the Ed25519-signed bundle at
    `report.reproducible.impact`, so this one leaves the building.

    NOTE ON WHAT THIS DOES AND DOES NOT PROVE. The live row for c01ad0d2 reads
    `8.2 / high`, headlined `Script.Ransom.AntisandboxUnhook` — an HTML readme
    rated as ransomware off the guest's anti-analysis checks. Replaying its 46
    real signals through TODAY's code gives 0.0 on BOTH axes: the impact half
    was already closed when `impact.assess` was moved onto the shared
    `capability_exclusions`, and the 8.2 on the row is a stale value written by
    older code that nothing has recomputed.

    So this asserts the property, not a delta. The stale rows are a separate
    problem with a separate fix — re-analysis — and one that no test can close.
    """
    signals = README_STATIC + README_HTML
    rated = impact.assess("script", signals, IOCs(), attributable=False)
    assert rated.base_score == 0.0, (rated.base_score, rated.severity)
    assert rated.severity == "none"


def test_the_samples_own_static_findings_are_untouched() -> None:
    """The guard is on the detonation, not on the file. `README.html`'s static
    signals are still read, still scored, still shown."""
    excluded = scoring.capability_exclusions("script", README_STATIC + README_HTML,
                                             attributable=False)
    assert not any(s.id in excluded for s in README_STATIC), excluded


def test_the_guests_indicators_do_not_move_the_number() -> None:
    """A C2 address the guest reached while "running" an HTML readme is the
    guest's address, not the sample's — and 12 of them reached `ioc_density`."""
    results = _results(IOCs(ips=[f"198.51.100.{n}" for n in range(12)]))
    assert scoring.scorable_ioc_total(results, "script", attributable=False) == 0
    assert scoring.scorable_ioc_total(results, "script", attributable=True) == 12


def test_no_capability_survives_either() -> None:
    excluded = scoring.capability_exclusions("script", ALL, attributable=False)
    caps = detect_capabilities([s for s in ALL if s.id not in excluded], IOCs())
    assert not caps & {"destruction", "injection"}, caps


def test_the_attck_exclusion_stays_narrow() -> None:
    """`inadmissible_dynamic_ids` exists so the ATT&CK mapping does not inherit
    `uncorroborated` and `family_ambient` from `capability_exclusions`. Widening
    it would quietly drop techniques from real malware this change never meant
    to touch."""
    narrow = scoring.inadmissible_dynamic_ids("pe", ALL, attributable=True)
    assert narrow == frozenset(), narrow
    blocked = scoring.inadmissible_dynamic_ids("pe", ALL, attributable=False)
    assert blocked == {s.id for s in ALL}, blocked


@pytest.mark.parametrize("fn", ["capability_exclusions", "scorable_ioc_total",
                                "inadmissible_dynamic_ids"])
def test_attributable_defaults_to_true(fn: str) -> None:
    """Every one of these defaults to "yes, this is the sample". A default of
    False would silently gag the whole product."""
    import inspect

    assert inspect.signature(getattr(scoring, fn)).parameters["attributable"].default is True
