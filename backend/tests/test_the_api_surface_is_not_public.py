"""The route list of a malware sandbox is reconnaissance, not documentation.

FastAPI mounts `/docs`, `/redoc` and `/openapi.json` unauthenticated by default,
so anyone who could reach this deployment could read its complete API: every
parameter, every schema, the admin endpoints, the worker seam. None of it is a
secret on its own and all of it is a map, handed over for free, of a service that
holds live malware.

Turned off is the easy answer and the wrong one — an operator integrating against
this needs the spec, and the alternative to publishing it is undocumented clients
written against guesses. So it moved behind the same dependency as everything
else.

Also here: `?status=zzz` returned `200 []`, which is byte-identical to the answer
for `?status=failed` on a healthy deployment. A typo in a dashboard filter read
as "nothing is failing".
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.engine.models import JobStatus
from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def auth(client):
    from app.config import get_settings

    settings = get_settings()
    key = settings.api_key_list[0] if settings.api_key_list else None
    if not key:
        pytest.skip("no API key configured in this environment")
    return {"X-API-Key": key}


# --- the schema is not anonymous ---------------------------------------------


@pytest.mark.parametrize("path", ["/openapi.json", "/docs", "/redoc"])
def test_the_default_schema_endpoints_are_gone(client, path) -> None:
    """Not 401 — gone. The SPA catch-all serves index.html for unknown non-API
    paths, so what matters is that no JSON schema and no Swagger page comes back.
    """
    response = client.get(path)
    body = response.text[:400].lower()
    assert "swagger" not in body, f"{path} still serves Swagger UI"
    assert "openapi" not in body, f"{path} still serves the schema"


def test_the_schema_needs_a_session(client) -> None:
    response = client.get("/api/openapi.json")
    assert response.status_code == 401, response.text[:200]


def test_the_docs_page_needs_a_session(client) -> None:
    assert client.get("/api/docs").status_code == 401


def test_an_authenticated_caller_gets_the_schema(client, auth) -> None:
    response = client.get("/api/openapi.json", headers=auth)
    assert response.status_code == 200, response.text[:200]
    document = response.json()
    assert document.get("openapi"), document.keys()
    assert "/api/jobs" in document.get("paths", {}), sorted(document.get("paths", {}))[:10]


# --- an unknown status is a mistake, not an empty page -----------------------


def test_an_unknown_status_is_rejected(client, auth) -> None:
    response = client.get("/api/jobs", params={"status": "zzz"}, headers=auth)
    assert response.status_code == 422, response.text[:200]
    detail = response.json()["detail"]
    # The message has to name the valid values, or the caller is left guessing
    # exactly as they were with the empty page.
    assert "completed" in detail and "failed" in detail, detail


@pytest.mark.parametrize("status", JobStatus.ALL)
def test_every_real_status_is_accepted(client, auth, status) -> None:
    response = client.get("/api/jobs", params={"status": status}, headers=auth)
    assert response.status_code == 200, (status, response.text[:200])
    assert "items" in response.json()


def test_no_status_still_lists_everything(client, auth) -> None:
    assert client.get("/api/jobs", headers=auth).status_code == 200


def test_the_shape_guard_still_runs_first(client, auth) -> None:
    """`?status=%00` is a 500 on PostgreSQL and fine on SQLite, so the regex that
    stops it must reject before the value check ever sees it — 422 either way,
    but from the parameter, not the handler."""
    for hostile in ("\x00", "A" * 40, "completed; drop table sandbox_jobs"):
        response = client.get("/api/jobs", params={"status": hostile}, headers=auth)
        assert response.status_code == 422, (hostile, response.status_code)
