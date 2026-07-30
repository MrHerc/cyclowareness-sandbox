"""Places where the product gave two different answers to the same question.

Not a theme anyone chose — it is what the audit kept finding. A number computed
one way on one screen and another way on the next; a claim the JSON export
scrubbed and the regulator's copy did not; a re-score path that had drifted from
the pipeline it was meant to mirror. Each is small on its own, and each makes a
reader stop trusting whichever half they read second.

The pattern in the fixes is the same too: ONE definition, called twice, rather
than two definitions that happen to agree today.
"""
from __future__ import annotations

import pytest

from app.engine import impact as impact_mod, mitre as mitre_mod, report as report_mod
from app.engine.contracts import IOCs, Signal


def _sig(sid: str, severity: str = "high", title: str = "") -> Signal:
    return Signal(id=sid, title=title or sid, severity=severity, detail="", evidence={})


# --- the impact rating and the verdict read the same evidence -----------------


def test_impact_ignores_the_signals_the_verdict_ignores() -> None:
    """A lone high-consequence signal is a lead, not a finding — and `verdict`
    already said so. `impact.assess` did not, so the same file read
    `Win32.Clean` and "Impact: medium" in one report."""
    from app.engine.scoring import uncorroborated

    lonely = [_sig("script.dynamic_execution", "high", "Builds and runs a command")]
    assert uncorroborated(lonely), "the premise: this signal is uncorroborated"

    rating = impact_mod.assess("pe", lonely, IOCs())
    assert rating.severity == "none", rating.to_dict()
    assert rating.base_score == 0.0


def test_impact_ignores_the_interpreter_the_verdict_ignores() -> None:
    """`family_ambient` means "this is PowerShell, not the script". A capability
    the sample does not have cannot be an impact it has either."""
    from app.engine.scoring import family_ambient

    ambient = sorted(family_ambient("script"))
    if not ambient:
        pytest.skip("no family-ambient signals defined for scripts")
    signals = [_sig(sid, "high") for sid in ambient]
    assert impact_mod.assess("script", signals, IOCs()).severity == "none"


def test_a_real_capability_is_still_rated() -> None:
    """The filter must not have turned the rating off."""
    corroborated = [
        _sig("script.credential_access", "high"),
        _sig("script.dynamic_execution", "high"),
    ]
    rating = impact_mod.assess("script", corroborated, IOCs())
    assert rating.severity != "none", rating.to_dict()
    assert rating.base_score > 0


# --- MITRE names the technique the signal is actually about -------------------


@pytest.mark.parametrize("signal_id", [
    "capev2.injection_createremotethread",
    "capev2.reads_memory_remote_process",
    "capev2.resumethread_remote_process",
    "capev2.terminates_remote_process",
])
def test_process_manipulation_is_not_command_and_control(signal_id) -> None:
    """The finding: "remote" matched as a bare substring, so four corpus signals
    about touching another process were filed under the tactic an analyst reads
    to find NETWORK activity."""
    techniques = mitre_mod.map_techniques([_sig(signal_id, "high")])
    tactics = {t["tactic"] for t in techniques}
    assert "Command and Control" not in tactics, techniques
    assert "T1055" in {t["technique_id"] for t in techniques}, techniques


def test_a_remote_template_is_still_command_and_control() -> None:
    """The one signal in the corpus for which "remote" meant the network."""
    techniques = mitre_mod.map_techniques([_sig("office.remote_template", "high")])
    assert "T1071" in {t["technique_id"] for t in techniques}, techniques


def test_ordinary_network_signals_are_unaffected() -> None:
    for signal_id in ("script.network_beacon", "capev2.dead_connect", "pe.http_request"):
        techniques = mitre_mod.map_techniques([_sig(signal_id, "high")])
        assert "T1071" in {t["technique_id"] for t in techniques}, (signal_id, techniques)


# --- the exports agree about the sandbox's own hostname -----------------------


class _Job:
    """The fields the report/incident layers read. Enough of a job to render."""

    def __init__(self, **kw):
        self.public_id = "case-1"
        self.original_name = "invoice.docx"
        self.sha256 = "a" * 64
        self.md5 = "b" * 32
        self.size_bytes = 1024
        self.mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        self.magic = "Microsoft Word"
        self.family = "office"
        self.status = "completed"
        self.risk_level = "high"
        self.final_score = 71.0
        self.rule_score = 70.0
        self.ai_score = 72.0
        self.source = "upload"
        self.submitted_url = None
        self.submitted_by = "analyst"
        self.extension_mismatch = 0
        self.iocs = {}
        self.analysis = {}
        self.score_breakdown = {}
        self.mitre = []
        self.impact = {}
        self.verdict = {"verdict": "malicious", "platform": "Office"}
        self.tiers = {}
        self.dynamic = {}
        self.created_at = self.started_at = self.completed_at = None
        self.first_completed_at = None
        self.sample_deleted_at = None
        self.engine_manifest = None
        self.feedback = None
        self.__dict__.update(kw)


HOSTNAME = "detonation-01"


def _detonated_job(**kw) -> _Job:
    dynamic = {
        "engine": "capev2",
        "worker": HOSTNAME,
        "ran": True,
        "signals": [],
        "unavailable_reason": None,
    }
    return _Job(
        dynamic=dynamic,
        tiers={
            "static": {"ran": True, "detail": "Parsers and YARA."},
            "dynamic": {
                "ran": True,
                "engine": "capev2",
                "worker": HOSTNAME,
                # The shape rows written before the scrub still have.
                "detail": f"Detonated on the capev2 worker ({HOSTNAME}).",
            },
        },
        analysis={
            "dynamic.capev2": {
                "analyzer": "dynamic.capev2", "ran": True,
                "signals": [{
                    "id": "capev2.process_creation", "title": "Created a process",
                    "severity": "high",
                    "detail": f"Observed on {HOSTNAME}.", "evidence": {},
                }],
                "facts": {}, "iocs": {},
            }
        },
        **kw,
    )


def test_the_json_export_scrubs_every_field_not_four_of_them() -> None:
    """Four fields were wrapped and the rest were not, so `signals` still carried
    the hostname of the machine that runs live malware for this organisation."""
    payload = report_mod.as_json(_detonated_job())
    assert HOSTNAME not in str(payload), [
        k for k, v in payload.items() if HOSTNAME in str(v)
    ]


def test_the_regulator_facing_record_scrubs_it_too() -> None:
    """The document most likely to be forwarded outside the organisation was the
    one export that did not scrub at all."""
    from app.engine import incident as incident_mod

    record = incident_mod.build(_detonated_job())
    assert HOSTNAME not in str(record)


def test_the_engine_name_survives_the_scrub() -> None:
    """`capev2` is a real input to the verdict. Only the MACHINE goes."""
    payload = report_mod.as_json(_detonated_job())
    assert "capev2" in str(payload)


# --- the STIX bundle states which tiers ran ----------------------------------


def test_the_bundle_does_not_claim_static_analysis_unconditionally() -> None:
    """It said "static analysis" in a literal, in the one export designed to be
    machine-ingested and forwarded."""
    stix2 = pytest.importorskip("stix2")
    bundle = report_mod.as_stix(_detonated_job())
    stix2.parse(bundle, allow_custom=False)

    described = " ".join(
        o.get("description", "") for o in bundle["objects"] if o["type"] == "malware"
    )
    if described:
        assert "static and dynamic analysis" in described, described

    notes = [o for o in bundle["objects"] if o["type"] == "note"]
    tiers = [n for n in notes if n["abstract"].startswith("Analysis tiers:")]
    assert len(tiers) == 1, [n["abstract"] for n in notes]
    assert "dynamic: ran" in tiers[0]["content"]


def test_a_tier_that_did_not_run_carries_its_caveat_into_the_bundle() -> None:
    stix2 = pytest.importorskip("stix2")
    job = _Job(tiers={
        "static": {"ran": True, "detail": "Parsers and YARA."},
        "dynamic": {"ran": False, "detail": "No worker attached."},
    })
    bundle = report_mod.as_stix(job)
    stix2.parse(bundle, allow_custom=False)
    notes = [o for o in bundle["objects"] if o["type"] == "note"]
    tiers = [n for n in notes if n["abstract"].startswith("Analysis tiers:")]
    assert "did not run" in tiers[0]["content"]
    assert "absent from this assessment" in tiers[0]["content"]


# --- STIX types match the values they carry ----------------------------------


@pytest.mark.parametrize("address,expected", [
    # Public addresses only: the export suppresses private, loopback,
    # link-local and RESERVED space, and Python counts the documentation ranges
    # (203.0.113.0/24, 2001:db8::/32) as private.
    ("8.8.8.8", "ipv4-addr"),
    ("2606:4700:4700::1111", "ipv6-addr"),
])
def test_an_ipv6_address_is_not_an_ipv4_addr(address, expected) -> None:
    """Every extracted IP was emitted as `ipv4-addr`, so a bundle carrying an
    IPv6 address published a pattern that can never match — silently
    unmatchable in every TIP that ingests it."""
    stix2 = pytest.importorskip("stix2")
    job = _Job(iocs={"ips": [address]}, verdict={"verdict": "malicious", "platform": "Office"})
    bundle = report_mod.as_stix(job)
    stix2.parse(bundle, allow_custom=False)
    text = str(bundle["objects"])
    assert expected in text, text[:400]
    if expected == "ipv6-addr":
        assert f"ipv4-addr:value = '{address}'" not in text


def test_a_malformed_address_does_not_break_the_export() -> None:
    """A report must not fail to export because one extracted value was junk."""
    assert report_mod._ip_type("not-an-address") == "ipv4-addr"


# --- the PDF's page-one box, and its arithmetic ------------------------------


def test_the_box_labelled_verdict_prints_the_verdict() -> None:
    """It printed the risk band. A signed installer read "VERDICT: HIGH" on page
    one while the engine's verdict, three pages later, was `clean`.

    Read back through pdfminer, which this project already depends on for the
    PDF analyzer, rather than adding a second PDF library to the test suite.
    """
    pytest.importorskip("reportlab")
    import io

    from pdfminer.high_level import extract_text

    job = _Job(verdict={"verdict": "clean", "platform": "Win32"}, risk_level="high")
    text = extract_text(io.BytesIO(report_mod.as_pdf(job)))
    assert "CLEAN" in text, text[:900]
    # And the box is relabelled, so the band is not presented as a verdict.
    assert "RISK BAND" not in text.split("SCORE")[0], text[:400]


def test_a_job_with_no_verdict_falls_back_to_the_band_and_says_so() -> None:
    """A job that never reached a verdict still has a band. Showing the band
    under the word VERDICT is the defect; showing it under RISK BAND is not."""
    pytest.importorskip("reportlab")
    import io

    from pdfminer.high_level import extract_text

    job = _Job(verdict={}, risk_level="critical")
    text = extract_text(io.BytesIO(report_mod.as_pdf(job)))
    assert "RISK BAND" in text, text[:400]
    assert "CRITICAL" in text


def test_the_printed_formula_is_the_one_the_job_was_scored_with() -> None:
    """The weights are tunable at runtime and the PDF stated a literal, so a
    reader reproducing the arithmetic got a different number than the score."""
    job = _Job(score_breakdown={"formula": "final = 0.8 x rule + 0.2 x model"})
    assert report_mod._score_formula(job) == "final = 0.8 x rule + 0.2 x model"


def test_a_row_written_before_the_formula_field_says_so() -> None:
    assert "default" in report_mod._score_formula(_Job(score_breakdown={}))


def test_the_risk_bands_come_from_the_table_that_defines_them() -> None:
    from app.engine.contracts import RISK_BANDS

    text = report_mod._band_text()
    for _threshold, label in RISK_BANDS:
        assert label in text, (label, text)
    assert "0–29 low" in text, text
