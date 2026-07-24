"""Database session management.

SQLAlchemy 2.0, driven entirely by ``DATABASE_URL``: SQLite for zero-setup
dev/demo, PostgreSQL (psycopg) in production. JSON columns use the portable
``sqlalchemy.JSON`` type, which maps to JSONB-compatible storage on PostgreSQL.
"""
from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings

settings = get_settings()

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


def init_db() -> None:
    """Create tables. Import models for their registration side effect first."""
    from .engine import models as _models  # noqa: F401

    Base.metadata.create_all(bind=engine)
