"""The upgrade path: an existing customer database must survive a release.

The failure these tests pin down was reproduced against a shipped build. The
schema was created by ``create_all()``, which CREATEs a table it has never seen
and silently ignores a column added to one it already has. So the release that
added the assessment columns to ``sandbox_jobs`` booted happily on a
previous-release database — ``/api/health`` returned 200 — and then every job
route raised ``no such column``. There was no upgrade and no rollback, which for
on-prem software is unshippable.

Each test drives ``init_db()`` against its own throwaway SQLite file by swapping
the module-level engine, so nothing here touches the suite's database.
"""
from __future__ import annotations

import json

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app import db as app_db
from app.engine.models import SandboxJob
from app.main import app

#: Added after the baseline. Absent from a previous-release database.
#: ``impact`` was added as ``cvss`` and renamed by 0003; either way it is the
#: column an older database does not have. ``sample_deleted_at`` arrived with
#: retention in 0005, ``tenant_id`` with multi-tenancy in 0006. Every new column
#: has to be listed here, and that is the
#: point: forgetting one makes the baseline-fidelity assertion fail loudly
#: rather than letting a migration drift from the schema it claims to reproduce.
POST_BASELINE_COLUMNS = (
    "impact", "verdict", "mitre", "sample_deleted_at", "tenant_id",
    "first_completed_at", "engine_manifest",
)


#: Ids a PREVIOUS RELEASE would have written. They are UUIDs because that
#: is what every release has ever minted — `git log -S 'public_id=' --all`
#: shows one generator, `str(uuid.uuid4())`, and all 1074 ids in the live
#: database parse as UUIDs. The fixture used to invent `legacy-job-2`, which
#: no release could produce, and that hid the missing validation on the path
#: parameter (a NUL byte there was a 500 on six routes).
_LEGACY_1 = "55555555-5555-4555-8555-555555555551"
_LEGACY_2 = "55555555-5555-4555-8555-555555555552"


def _build_previous_release_schema(engine: sa.Engine) -> None:
    """Exactly what ``create_all()`` produced before those columns existed.

    Derived from the live model with the new columns removed, rather than from
    the baseline migration: a database built from the migration would agree with
    the migration by construction, and it is the *old model* this has to match.
    """
    metadata = sa.MetaData()
    table = SandboxJob.__table__.to_metadata(metadata)
    for name in POST_BASELINE_COLUMNS:
        table._columns.remove(table.c[name])
    # Indexes are copied by to_metadata and do NOT follow the column out, so an
    # index over a removed column survives and CREATE INDEX then fails with
    # "no such column". Every post-baseline column so far happened to be
    # unindexed, which is why this only surfaced with `tenant_id` — the helper
    # was wrong all along and nothing had asked it the question.
    dropped = set(POST_BASELINE_COLUMNS)
    for index in list(table.indexes):
        if {c.name for c in index.columns} & dropped:
            table.indexes.discard(index)
    metadata.create_all(engine)


def _insert_legacy_job(engine: sa.Engine, public_id: str) -> None:
    """A row written by the previous release, i.e. the customer's evidence."""
    with engine.begin() as connection:
        connection.execute(
            sa.text(
                "INSERT INTO sandbox_jobs (public_id, source, original_name, sha256,"
                " md5, size_bytes, mime, magic, family, extension_mismatch, status,"
                " stage, tiers, analysis, iocs, score_breakdown, rule_score, ai_score,"
                " final_score, risk_level, dynamic, created_at)"
                " VALUES (:pid, 'upload', 'invoice.doc', 'a' || :pid, 'b', 12, "
                "'application/msword', 'CDF', 'office', 0, 'completed', 'done',"
                " '{}', '{}', '{}', '{}', 4.0, 0.0, 4.0, 'medium', '{}',"
                " '2026-01-01 00:00:00')"
            ),
            {"pid": public_id},
        )


def _columns(engine: sa.Engine) -> set[str]:
    return {c["name"] for c in sa.inspect(engine).get_columns("sandbox_jobs")}


def _head_revision() -> str:
    """The latest revision, read from the migration scripts.

    Not hardcoded: every release that adds a revision would otherwise have to
    edit each assertion below, and the thing under test is "init_db reaches head",
    not "init_db reaches this particular string".
    """
    from alembic.script import ScriptDirectory

    return ScriptDirectory.from_config(app_db.alembic_config()).get_current_head()


def _revision(engine: sa.Engine) -> str | None:
    with engine.connect() as connection:
        if "alembic_version" not in sa.inspect(connection).get_table_names():
            return None
        return connection.execute(sa.text("SELECT version_num FROM alembic_version")).scalar()


def _alembic(engine: sa.Engine, action: str, revision: str) -> None:
    """Run an Alembic command against a specific engine (``upgrade``/``downgrade``)."""
    from alembic import command

    config = app_db.alembic_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        getattr(command, action)(config, revision)


@pytest.fixture()
def temp_engine(tmp_path, monkeypatch):
    """An empty SQLite file bound in place of the service's engine.

    ``init_db()`` and ``get_db()`` both read these module globals at call time,
    so swapping them redirects the whole application — routes included — at this
    database for the duration of one test.
    """
    url = "sqlite:///" + str(tmp_path / "upgrade.db").replace("\\", "/")
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


# --- the reported failure ----------------------------------------------------
def test_previous_release_database_reproduces_the_reported_failure(temp_engine):
    """Guards the reproduction itself: without the upgrade, job queries fail."""
    _build_previous_release_schema(temp_engine)
    assert not _columns(temp_engine) & set(POST_BASELINE_COLUMNS)

    session = sessionmaker(bind=temp_engine)()
    try:
        with pytest.raises(OperationalError) as excinfo:
            session.execute(sa.select(SandboxJob)).scalars().all()
    finally:
        session.close()
    assert "impact" in str(excinfo.value)


def test_init_db_upgrades_a_previous_release_database(temp_engine):
    _build_previous_release_schema(temp_engine)
    _insert_legacy_job(temp_engine, _LEGACY_1)

    app_db.init_db()

    assert set(POST_BASELINE_COLUMNS) <= _columns(temp_engine)
    assert _revision(temp_engine) == _head_revision()

    # The pre-existing evidence survived, and the new columns are populated with
    # values the ORM can load rather than NULLs a non-nullable column rejects.
    session = sessionmaker(bind=temp_engine)()
    try:
        job = session.execute(
            sa.select(SandboxJob).where(SandboxJob.public_id == _LEGACY_1)
        ).scalar_one()
        assert job.original_name == "invoice.doc"
        assert job.final_score == 4.0
        assert job.impact == {}
        assert job.verdict == {}
        assert job.mitre == []
    finally:
        session.close()


def test_api_serves_a_previous_release_database_after_boot(temp_engine):
    """End to end: the routes that returned 500 now answer, over the old data."""
    _build_previous_release_schema(temp_engine)
    _insert_legacy_job(temp_engine, _LEGACY_2)

    # The lifespan runs init_db(), which is the upgrade an operator gets for free.
    with TestClient(app) as client:
        assert client.get("/api/health").status_code == 200

        login = client.post(
            "/api/auth/login", json={"username": "analyst", "password": "analyst"}
        )
        assert login.status_code == 200, login.text
        headers = {"Authorization": f"Bearer {login.json()['token']}"}

        listing = client.get("/api/jobs", headers=headers)
        assert listing.status_code == 200, listing.text
        assert _LEGACY_2 in [job["public_id"] for job in listing.json()["items"]]

        detail = client.get(f"/api/result/{_LEGACY_2}", headers=headers)
        assert detail.status_code == 200, detail.text


def test_current_release_database_without_alembic_is_adopted_in_place(temp_engine):
    """The developer/demo database: built by the old ``create_all()`` from the
    current models, so it is already at the current schema but has no version
    table. It must be adopted, not rebuilt, and its rows must survive."""
    app_db.Base.metadata.create_all(temp_engine)
    session = sessionmaker(bind=temp_engine)()
    try:
        session.add(SandboxJob(public_id="44444444-4444-4444-8444-444444444444", original_name="invoice.doc"))
        session.commit()
    finally:
        session.close()

    app_db.init_db()

    assert _revision(temp_engine) == _head_revision()
    with temp_engine.connect() as connection:
        count = connection.execute(sa.text("SELECT count(*) FROM sandbox_jobs")).scalar()
    assert count == 1


# --- a brand-new install -----------------------------------------------------
def test_fresh_database_is_created_by_the_migrations(temp_engine):
    app_db.init_db()

    assert "sandbox_jobs" in sa.inspect(temp_engine).get_table_names()
    assert set(POST_BASELINE_COLUMNS) <= _columns(temp_engine)
    assert _revision(temp_engine) == _head_revision()


def test_migrated_schema_matches_the_models(temp_engine):
    """No drift: what the migrations build is what the ORM expects to find.

    This is the check that would have caught the original defect — a column on a
    model with no migration behind it shows up here as an outstanding change.
    """
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    app_db.init_db()
    with temp_engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        assert compare_metadata(context, app_db.Base.metadata) == []


def test_init_db_is_idempotent(temp_engine):
    """The lifespan and the test fixtures both call it; a second run is a no-op."""
    app_db.init_db()
    app_db.init_db()
    assert _revision(temp_engine) == _head_revision()


# --- baseline fidelity and rollback ------------------------------------------
def test_baseline_reproduces_the_previous_release_schema(tmp_path):
    """Stamping an old database at the baseline is only honest if they match."""
    from_migration = sa.create_engine(
        "sqlite:///" + str(tmp_path / "baseline.db").replace("\\", "/"), future=True
    )
    from_old_model = sa.create_engine(
        "sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"), future=True
    )
    try:
        _alembic(from_migration, "upgrade", "0001_baseline")
        _build_previous_release_schema(from_old_model)

        migrated = sa.inspect(from_migration)
        legacy = sa.inspect(from_old_model)
        assert _columns(from_migration) == _columns(from_old_model)
        assert {i["name"] for i in migrated.get_indexes("sandbox_jobs")} == {
            i["name"] for i in legacy.get_indexes("sandbox_jobs")
        }
        assert {
            (c["name"], c["nullable"], str(c["type"]))
            for c in migrated.get_columns("sandbox_jobs")
        } == {
            (c["name"], c["nullable"], str(c["type"]))
            for c in legacy.get_columns("sandbox_jobs")
        }
    finally:
        from_migration.dispose()
        from_old_model.dispose()


def test_downgrade_and_re_upgrade_preserve_rows(temp_engine):
    """A release can be rolled back. SQLite cannot DROP COLUMN in place, so this
    also proves the batch_alter_table form of the revision actually works."""
    app_db.init_db()
    _insert_legacy_job(temp_engine, "rollback-job")

    _alembic(temp_engine, "downgrade", "0001_baseline")
    assert not _columns(temp_engine) & set(POST_BASELINE_COLUMNS)
    assert _revision(temp_engine) == "0001_baseline"

    _alembic(temp_engine, "upgrade", "head")
    assert set(POST_BASELINE_COLUMNS) <= _columns(temp_engine)

    with temp_engine.connect() as connection:
        row = connection.execute(
            sa.text(
                "SELECT original_name, impact FROM sandbox_jobs WHERE public_id = 'rollback-job'"
            )
        ).one()
    assert row[0] == "invoice.doc"
    assert json.loads(row[1]) == {}
