"""Two customers on one deployment cannot see each other's evidence.

This is the test that decides whether tenancy exists. The column, the migration
and the WHERE clauses are all just machinery; if a caller holding tenant A's key
can read one byte belonging to tenant B, none of it happened.

So this file is written from the outside — real HTTP requests with real
credentials — and it enumerates every route that returns job data rather than
sampling a couple. A boundary is only as good as its least-checked door, and the
way this fails in practice is never the door someone thought about.
"""
from __future__ import annotations

import io

import pytest

from app.config import get_settings

ACME_KEY = "acme:key-acme-secret"
GLOBEX_KEY = "globex:key-globex-secret"
BARE_KEY = "key-with-no-tenant"


@pytest.fixture(autouse=True)
def two_tenants(monkeypatch):
    """Three credentials: two named tenants and one bare (legacy) key."""
    monkeypatch.setenv("API_KEYS", f"{ACME_KEY},{GLOBEX_KEY},{BARE_KEY}")
    monkeypatch.setenv("DEFAULT_TENANT", "default")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _submit(client, key: str, name: str, payload: bytes) -> str:
    response = client.post(
        "/api/analyze",
        files={"file": (name, io.BytesIO(payload), "application/octet-stream")},
        headers={"X-API-Key": key.split(":", 1)[1]},
    )
    assert response.status_code == 201, response.text
    return response.json()["public_id"]


def _headers(key: str) -> dict[str, str]:
    return {"X-API-Key": key.split(":", 1)[1]}


@pytest.fixture()
def acme_job(client) -> str:
    return _submit(client, ACME_KEY, "acme-secret.ps1", b"Write-Host 'acme internal'\n")


# --- the boundary itself -----------------------------------------------------


#: Every route that takes a public_id and returns something derived from the job.
#: Listed exhaustively rather than sampled: the one that leaks will be the one
#: nobody added to the list.
JOB_ROUTES = [
    "/api/result/{id}",
    "/api/jobs/{id}/export.json",
    "/api/jobs/{id}/export.stix",
    "/api/jobs/{id}/export.incident",
    "/api/jobs/{id}/export.pdf",
    "/api/jobs/{id}/export.signed",
]


@pytest.mark.parametrize("route", JOB_ROUTES)
def test_another_tenant_cannot_read_a_job_by_any_route(client, acme_job, route) -> None:
    response = client.get(route.format(id=acme_job), headers=_headers(GLOBEX_KEY))
    assert response.status_code == 404, (
        f"{route} leaked tenant acme's job to globex: {response.status_code}"
    )


@pytest.mark.parametrize("route", JOB_ROUTES)
def test_the_owning_tenant_still_gets_its_own_job(client, acme_job, route) -> None:
    """The other half. An isolation bug that denies everyone is not a fix."""
    response = client.get(route.format(id=acme_job), headers=_headers(ACME_KEY))
    assert response.status_code == 200, (
        f"{route} denied tenant acme its own job: {response.status_code} {response.text[:200]}"
    )


def test_it_answers_404_not_403(client, acme_job) -> None:
    """403 confirms the job exists, which is itself the leak.

    A caller who can tell "not yours" from "no such job" can enumerate public ids
    and learn how much a competitor on the same deployment is analysing, without
    ever reading a report.
    """
    known = client.get(f"/api/result/{acme_job}", headers=_headers(GLOBEX_KEY))
    unknown = client.get(
        "/api/result/00000000-0000-0000-0000-000000000000", headers=_headers(GLOBEX_KEY)
    )
    assert known.status_code == unknown.status_code == 404
    assert known.json() == unknown.json()


def test_the_job_list_shows_only_your_own(client) -> None:
    acme = _submit(client, ACME_KEY, "acme-list.ps1", b"Write-Host 'a'\n")
    globex = _submit(client, GLOBEX_KEY, "globex-list.ps1", b"Write-Host 'b'\n")

    seen = {
        j["public_id"]
        for j in client.get("/api/jobs?limit=200", headers=_headers(ACME_KEY)).json()
    }
    assert acme in seen
    assert globex not in seen, "the job list leaked another tenant's submission"


def test_mutating_routes_are_scoped_too(client, acme_job) -> None:
    """A write is a read first: it has to find the row before it can change it."""
    for path, body in (
        (f"/api/jobs/{acme_job}/feedback", {"verdict": "false_positive"}),
        (f"/api/jobs/{acme_job}/password", {"password": "x"}),
        (f"/api/jobs/{acme_job}/reanalyze", None),
    ):
        response = client.post(path, json=body, headers=_headers(GLOBEX_KEY))
        assert response.status_code == 404, f"{path} was reachable across tenants"


# --- how a job gets its owner ------------------------------------------------


def test_a_bare_key_lands_in_the_default_tenant(client) -> None:
    """An existing deployment's key keeps working and keeps its data."""
    public_id = _submit(client, f"x:{BARE_KEY}", "legacy.ps1", b"Write-Host 'legacy'\n")
    assert client.get(f"/api/result/{public_id}", headers={"X-API-Key": BARE_KEY}).status_code == 200
    assert client.get(f"/api/result/{public_id}", headers=_headers(ACME_KEY)).status_code == 404


def test_archive_members_inherit_the_archive_owner(client) -> None:
    """The unpack stage runs in the background with no request identity at all.

    If a child took the default tenant rather than its parent's, a customer's
    archive contents would land somewhere they never submitted — a leak nobody
    performed and nobody could see coming.
    """
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("inner.ps1", "Write-Host 'inside acme archive'\n")
    public_id = _submit(client, ACME_KEY, "acme.zip", buffer.getvalue())

    # Unpacking happens in the background, so the members do not exist the
    # instant the submission returns.
    detail = None
    for _ in range(60):
        response = client.get(f"/api/result/{public_id}", headers=_headers(ACME_KEY))
        assert response.status_code == 200
        detail = response
        if response.json().get("status") in ("completed", "failed", "awaiting_password"):
            break
    assert detail is not None
    children = detail.json().get("children") or []
    assert children, "the archive produced no members to check"
    for child in children:
        child_id = child["public_id"]
        assert client.get(
            f"/api/result/{child_id}", headers=_headers(ACME_KEY)
        ).status_code == 200
        assert client.get(
            f"/api/result/{child_id}", headers=_headers(GLOBEX_KEY)
        ).status_code == 404, "an archive member was visible to another tenant"


def test_a_job_cannot_be_created_without_an_owner() -> None:
    """No silent default. A job with no stated owner is a bug, not a default.

    The failure mode this refuses: a new code path forgets the tenant, the job
    silently lands in `default`, and it is then invisible to the customer who
    submitted it and visible to whoever holds a bare key.
    """
    from app.engine import pipeline

    with pytest.raises(ValueError, match="tenant"):
        pipeline.new_job(
            None, object(), original_name="orphan.exe"  # type: ignore[arg-type]
        )


# --- the audit trail ---------------------------------------------------------


def test_the_audit_trail_is_scoped(client) -> None:
    """Reading it is privileged, and it names files and addresses."""
    from app import audit
    from app.db import session_scope

    _submit(client, ACME_KEY, "acme-audit.ps1", b"Write-Host 'a'\n")
    _submit(client, GLOBEX_KEY, "globex-audit.ps1", b"Write-Host 'b'\n")

    db = session_scope()
    try:
        _total, acme_events = audit.query(db, tenant="acme", limit=500)
        names = " ".join(str(e.detail) for e in acme_events)
    finally:
        db.close()
    assert "acme-audit.ps1" in names
    assert "globex-audit.ps1" not in names, "the audit trail leaked another tenant's filename"


def test_the_audit_total_is_scoped_as_well(client) -> None:
    """A count over every tenant reports another customer's volume."""
    from app import audit
    from app.db import session_scope

    _submit(client, ACME_KEY, "acme-count.ps1", b"Write-Host 'a'\n")
    for _ in range(3):
        _submit(client, GLOBEX_KEY, "globex-count.ps1", b"Write-Host 'b'\n")

    db = session_scope()
    try:
        acme_total, _ = audit.query(db, tenant="acme", limit=1)
        globex_total, _ = audit.query(db, tenant="globex", limit=1)
        everything, _ = audit.query(db, limit=1)
    finally:
        db.close()
    assert acme_total < everything
    assert globex_total < everything
