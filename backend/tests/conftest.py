"""Shared fixtures.

The single most important thing this file does is set the environment **before**
anything under ``app`` is imported. ``app.config.get_settings()`` is ``lru_cache``d
and ``app.db`` binds its SQLAlchemy engine to ``DATABASE_URL`` at import time, so a
DATABASE_URL set after the first ``import app.db`` would be ignored and the tests
would run against the developer's real database. Setting the environment at module
top — which pytest executes before it imports any test module in this directory —
is what keeps the suite hermetic.

The quarantine and the database both live in throwaway temp directories, so a test
never touches the real quarantine tree and never persists a row past the run.
"""
from __future__ import annotations

import os
import tempfile

# --- environment, set BEFORE importing the app -------------------------------
# A fresh, isolated posture. tmp_path_factory cannot be used here because it only
# exists inside a fixture, and this must run at import time.
_TMP_ROOT = tempfile.mkdtemp(prefix="cyclowareness-tests-")
_QUARANTINE = os.path.join(_TMP_ROOT, "quarantine")
_DB_FILE = os.path.join(_TMP_ROOT, "test.db")
os.makedirs(_QUARANTINE, exist_ok=True)

os.environ["APP_ENV"] = "demo"
os.environ["SANDBOX_QUARANTINE"] = _QUARANTINE
os.environ["DATABASE_URL"] = "sqlite:///" + _DB_FILE.replace("\\", "/")
os.environ["DYNAMIC_WORKER_TOKEN"] = "test-token"
# Never let a real dynamic worker be considered "attached" during the suite.
os.environ.pop("SANDBOX_DYNAMIC_WORKER", None)
# Deterministic session tokens across the process.
os.environ.setdefault("SECRET_KEY", "test-only-secret-key")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

# Safe to import app modules now that the environment is in place.
from app.db import init_db, session_scope  # noqa: E402
from app import ratelimit  # noqa: E402
from app.engine import scoring  # noqa: E402
from app.main import app  # noqa: E402


#: The worker token configured for the suite (see require_worker in api/dynamic).
WORKER_TOKEN = "test-token"


@pytest.fixture(autouse=True)
def _reset_scoring_weights():
    """Scoring weights are process-global and some tests tune them. Reset around
    every test so the admin-weights test cannot leak into the pipeline tests."""
    scoring.reset_weights()
    yield
    scoring.reset_weights()


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Give every test a clean rate-limit budget.

    The limiter is process-global and the suite logs in a few hundred times,
    which is legitimate traffic shaped exactly like a brute-force attempt. The
    fix is to reset it per test rather than to loosen the production limits
    until the suite fits under them — ten logins per five minutes is the right
    number for a real deployment, and it should stay that way.
    """
    ratelimit.limiter.reset()
    yield


@pytest.fixture()
def client():
    """A TestClient used as a context manager so the app's lifespan runs — that
    is what calls ``init_db()`` and creates the tables."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def db():
    """A raw database session for tests that drive the engine directly rather
    than through the HTTP layer."""
    init_db()
    session = session_scope()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def auth(client):
    """Authorization headers for the seeded analyst account (analyst/analyst)."""
    response = client.post(
        "/api/auth/login", json={"username": "analyst", "password": "analyst"}
    )
    assert response.status_code == 200, response.text
    token = response.json()["token"]
    return {"Authorization": f"Bearer {token}"}
