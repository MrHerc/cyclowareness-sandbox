"""Database session management.

SQLAlchemy 2.0, driven entirely by ``DATABASE_URL``: SQLite for zero-setup
dev/demo, PostgreSQL (psycopg) in production. JSON columns use the portable
``sqlalchemy.JSON`` type, which maps to JSONB-compatible storage on PostgreSQL.

The schema is owned by Alembic (see ../alembic.ini and ../migrations), not by
``create_all()``: this is an on-prem product, and ``create_all()`` cannot alter a
table it has already seen, so a release that added a column bricked every job
route on an existing customer database while /api/health still said 200.
"""
from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import Connection, create_engine, inspect
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings

settings = get_settings()

#: The backend root — holds alembic.ini and migrations/. Resolved from this
#: file rather than the working directory, because the container starts uvicorn
#: from /app while an operator may run anything from anywhere.
BACKEND_DIR = Path(__file__).resolve().parent.parent

#: The first revision. A database created before Alembic existed matches it
#: exactly, which is what makes adopting one by stamping safe.
BASELINE_REVISION = "0001_baseline"
#: The revision that added the columns below. Named explicitly rather than as
#: "head" so that adopting a pre-Alembic database still runs every revision
#: added after it — stamping "head" would skip them.
CVSS_REVISION = "0002_cvss_verdict_mitre"
#: Columns added by CVSS_REVISION; their presence dates a pre-Alembic database.
_POST_BASELINE_COLUMNS = {"cvss", "verdict", "mitre"}
#: The revision that renamed `cvss` to `impact`. A pre-Alembic database built by
#: create_all() from the *current* models already has the new name, so it must be
#: stamped here — stamping CVSS_REVISION would send it into a rename of a column
#: it does not have.
IMPACT_REVISION = "0003_impact_rating"
_IMPACT_COLUMNS = {"impact", "verdict", "mitre"}
#: The revision that added retention's deletion marker.
RETENTION_REVISION = "0005_sample_deleted_at"
_RETENTION_COLUMNS = {"sample_deleted_at", "impact", "verdict", "mitre"}

#: Newest revision first. A pre-Alembic database is stamped at the first entry
#: whose marker columns are all present, then upgraded from there.
#:
#: A ladder rather than a chain of ifs because it has to be EXTENDED, not
#: rewritten, and forgetting to extend it is not a cosmetic miss: a customer
#: whose database was built by the old ``create_all()`` gets stamped too low,
#: the next migration re-adds a column that already exists, and the service
#: fails to boot. Every migration that adds a column adds a rung here.
_ADOPTION_LADDER: tuple[tuple[str, set[str]], ...] = (
    (RETENTION_REVISION, _RETENTION_COLUMNS),
    (IMPACT_REVISION, _IMPACT_COLUMNS),
    (CVSS_REVISION, _POST_BASELINE_COLUMNS),
)

connect_args: dict = {}
if settings.database_url.startswith("sqlite"):
    # Background analysis threads and request handlers share the SQLite file.
    connect_args = {"check_same_thread": False}

engine = create_engine(settings.database_url, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: one session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def session_scope() -> Session:
    """A fresh session for background tasks (caller must close)."""
    return SessionLocal()


def alembic_config():
    """The Alembic configuration the service and the CLI share."""
    from alembic.config import Config

    return Config(str(BACKEND_DIR / "alembic.ini"))


def _legacy_stamp_target(connection: Connection) -> str | None:
    """Which revision an un-versioned database already satisfies, if any.

    Installs made before Alembic have the tables but no ``alembic_version``, so
    ``upgrade head`` would try to CREATE a table that exists and abort the boot.
    Reading the columns tells us which release built them, so the database can be
    stamped at that point and then upgraded — the same two steps an operator
    would run by hand, minus the outage while they work out which one to run.

    Returns ``None`` when there is nothing to adopt: an empty database (the
    migrations build it) or one Alembic already manages.
    """
    tables = set(inspect(connection).get_table_names())
    if "alembic_version" in tables or "sandbox_jobs" not in tables:
        return None
    columns = {c["name"] for c in inspect(connection).get_columns("sandbox_jobs")}
    for revision, markers in _ADOPTION_LADDER:
        if markers <= columns:
            return revision
    return BASELINE_REVISION


def init_db() -> None:
    """Bring the database to the current schema, creating it if it is empty.

    Migrations run on the engine this process already owns rather than on a
    connection Alembic opens for itself: on SQLite the two would contend for the
    same write lock, and the boot would hang instead of failing loudly.
    """
    from alembic import command

    from .engine import models as _models  # noqa: F401  — registers the tables

    config = alembic_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        stamp_target = _legacy_stamp_target(connection)
        if stamp_target is not None:
            command.stamp(config, stamp_target)
        command.upgrade(config, "head")
