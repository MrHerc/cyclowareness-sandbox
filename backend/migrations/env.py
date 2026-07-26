"""Alembic environment for Cyclowareness Sandbox.

Two callers share this file:

* the ``alembic`` CLI, which opens its own connection from ``DATABASE_URL``;
* ``app.db.init_db()``, which injects the service's already-open connection
  through ``config.attributes["connection"]`` so boot-time migrations run on the
  one engine the process owns. On SQLite a second connection would contend with
  it for the write lock.

The URL always comes from ``app.config`` rather than from alembic.ini, so an
operator running the CLI cannot migrate a different database than the one the
service will open.
"""
from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine

from app.config import get_settings
from app.db import Base
from app.engine import models as _models  # noqa: F401  — registers the tables

config = context.config

# Only the CLI takes its logging from the ini. fileConfig() disables existing
# loggers, which mid-boot would silently kill the service's own logging, so it
# is skipped whenever a connection was handed to us.
if config.config_file_name is not None and config.attributes.get("connection") is None:
    fileConfig(config.config_file_name)

#: Autogenerate compares the live schema against this. Both SQLite and
#: PostgreSQL are supported targets, so every column type used here is portable.
target_metadata = Base.metadata


def _database_url() -> str:
    return get_settings().database_url


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of executing it (``alembic upgrade --sql``)."""
    url = _database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # SQLite cannot ALTER a column or drop one in place; batch mode rewrites
        # the table instead. Harmless on PostgreSQL, which renders plain ALTERs.
        render_as_batch=_is_sqlite(url),
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=connection.dialect.name == "sqlite",
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _run(connection)
        return

    url = _database_url()
    connect_args = {"check_same_thread": False} if _is_sqlite(url) else {}
    engine = create_engine(url, connect_args=connect_args, future=True)
    try:
        with engine.connect() as conn:
            _run(conn)
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
