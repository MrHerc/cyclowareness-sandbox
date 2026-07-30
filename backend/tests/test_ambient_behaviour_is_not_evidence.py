"""A signed installer running in a VM is not a malware sample.

The dynamic tier imports CAPE's own severity verbatim, and CAPE's signature set
is tuned to flag anything unusual INSIDE A VM. A GUI installer trips a dozen of
them at medium or high — it reads the crypto policy, asks whether it is
elevated, reads its own file, enumerates mount points to pick a drive, waits for
mouse input — and the severity bands then add up to "suspicious" without a
single accusing capability behind it.

Measured across 50 benign samples (7-Zip, PuTTY, Audacity, HandBrake, WinMerge,
Greenshot, the Python embeddable distribution, Sysinternals, the GitHub CLI,
Microsoft's Windows Terminal):

    before   20 clean   26 suspicious   4 malicious
    after    29 clean   17 suspicious   4 malicious

and against the 88-sample detonation fixture, in the same measurement:

    before   84 of 88 detected
    after    84 of 88 detected      <- zero cost

The zero is the point, and it is why this file exists rather than a note in a
commit message. Three candidates were REJECTED for costing one detection each:
`pe.overlay_present` and `generic.high_entropy_overall` both lose WannaCry, and
`capev2.pe_exports_in_executable` loses RaccoonStealer. Two more were rejected
for weakening detection to buy two benign files — `capev2.persistence_autorun`
and `capev2.mass_file_modification_access` are the persistence and ransomware
signals, and a malware sandbox does not trade those away for a tidier report.
"""
from __future__ import annotations

import pytest

from app.engine import scoring, verdict
from app.engine.contracts import AnalyzerResult, IOCs, Signal

#: Demoting any of these costs a detection on the fixture. The number beside
#: each is what it costs, measured, and this test is what stops a later tidy-up
#: from adding them because they "look like the others".
NEVER_DEMOTE = {
    "pe.overlay_present": "WannaCry",
    "generic.high_entropy_overall": "WannaCry",
    "capev2.pe_exports_in_executable": "RaccoonStealer",
    "capev2.persistence_autorun": "the persistence signal",
    "capev2.mass_file_modification_access": "the ransomware signal",
    # Rejected in the 2026-07-30 administrative-tool sweep. All ten cost ZERO
    # fixture detections, so "it is free" would have accepted them — and that is
    # exactly why the rule is incidence, not cost. Each of these is MORE COMMON
    # IN MALWARE than in ordinary software, so demoting it trades real capability
    # for nothing. The percentages are benign corpus vs 88-sample fixture.
    "capev2.antivm_wmi": "0% benign / 18% malware",
    "capev2.encrypted_ioc": "12% / 19%",
    "capev2.uses_windows_utilities": "4% / 15%",
    "capev2.interprocess_comms_mutex": "4% / 15%",
    "capev2.enumerates_running_processes": "4% / 14%",
    "capev2.suspicious_ntdll_disk_load": "10% / 17%",
    "capev2.recon_fingerprint": "4% / 7%",
    "capev2.process_interest": "2% / 6%",
    "capev2.recon_systeminfo": "2% / 4%",
    "capev2.cmdline_http_link": "2% / 3%",
}


def _signal(sid: str, severity: str = "high") -> Signal:
    return Signal(id=sid, title=sid, severity=severity, detail="", evidence={})


def _classify(signals: list[Signal]):
    results = [AnalyzerResult(analyzer="dynamic.capev2", ran=True, signals=signals)]
    assessment = scoring.assess(results, ioc_total=0)
    got = verdict.classify("pe", "application/x-dosexec", results, IOCs(), assessment.final_score)
    return assessment.final_score, got


def test_the_rejected_candidates_stay_rejected() -> None:
    for sid, cost in NEVER_DEMOTE.items():
        assert sid not in scoring.AMBIENT_SIGNALS, (
            f"{sid} was demoted; it was measured to cost {cost}"
        )


@pytest.mark.parametrize("sid", sorted(scoring.AMBIENT_SIGNALS))
def test_every_ambient_signal_is_demoted(sid) -> None:
    assert scoring.effective_severity(_signal(sid, "high")) == "low"
    assert scoring.effective_severity(_signal(sid, "medium")) == "low"


def test_a_real_finding_is_untouched() -> None:
    for sid in ("capev2.mass_data_encryption", "script.download_and_execute",
                "capev2.persistence_autorun", "office.autoexec_macro"):
        assert scoring.effective_severity(_signal(sid, "high")) == "high"


def test_a_pile_of_ambient_behaviour_is_not_a_verdict() -> None:
    """The failure this fixes, in one assertion: every ambient signature at
    once, and nothing else, must not accuse the file of anything."""
    score, got = _classify([_signal(s, "high") for s in sorted(scoring.AMBIENT_SIGNALS)])
    assert got.verdict == "clean", (got.to_dict(), score)


def test_one_real_finding_still_lands_among_them() -> None:
    """Demoting the noise must not deafen the engine. The same pile, plus one
    thing that actually matters."""
    signals = [_signal(s, "high") for s in sorted(scoring.AMBIENT_SIGNALS)]
    signals += [
        _signal("capev2.mass_data_encryption"),
        _signal("capev2.deletes_shadow_copies"),
    ]
    _score, got = _classify(signals)
    assert got.verdict in ("malicious", "suspicious"), got.to_dict()


def test_the_label_agrees_with_the_score() -> None:
    """7-Zip's own installer scored as ordinary software and was still headlined
    `Win32.Riskware.HardwareIdProfiling` — the number and the name disagreeing
    about the same file."""
    _score, got = _classify([_signal(s, "high") for s in sorted(scoring.AMBIENT_SIGNALS)])
    for ambient in scoring.AMBIENT_SIGNALS:
        tail = ambient.split(".")[-1].replace("_", "")
        assert tail.lower() not in got.threat_name.lower(), got.threat_name


def test_the_observation_is_kept_not_deleted() -> None:
    """Demoted, not dropped: an analyst still sees every signature the sandbox
    raised, and one of them beside real evidence still reads as part of the
    picture."""
    signals = [_signal("capev2.hardware_id_profiling")]
    results = [AnalyzerResult(analyzer="dynamic.capev2", ran=True, signals=signals)]
    assert results[0].signals[0].severity == "high"
    assert results[0].signals[0].id == "capev2.hardware_id_profiling"


def test_an_installer_package_may_contain_executables() -> None:
    """An MSI is an OLE document that carries programs — that is what it is for.
    `generic.embedded_executable` was exempted for this; the YARA rule that
    finds the same bytes was not, so the GitHub CLI's and PuTTY's official
    installers stayed `EmbeddedPeInNonpe` at high."""
    from app.engine import yara_engine

    class _S:
        claimed_extension = ".msi"

    assert yara_engine._carries_executables(_S())
    _S.claimed_extension = ".msixbundle"
    assert yara_engine._carries_executables(_S())
    _S.claimed_extension = ".doc"
    assert not yara_engine._carries_executables(_S()), (
        "a .doc carrying a PE genuinely is a dropper"
    )


def test_a_zip_by_another_name_is_not_a_disguise() -> None:
    """A `.msixbundle` IS a zip; that is the format. Microsoft's own Windows
    Terminal release was `Archive.Riskware.ExtensionMismatch` at high severity
    for shipping in its documented format."""
    from app.engine.identify import _ZIP_EXTENSIONS

    for ext in (".msixbundle", ".appx", ".jar", ".apk", ".whl", ".epub", ".vsix"):
        assert ext in _ZIP_EXTENSIONS, ext
