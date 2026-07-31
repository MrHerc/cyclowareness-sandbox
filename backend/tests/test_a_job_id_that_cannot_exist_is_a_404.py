"""A NUL byte in a job id was a 500 on six routes, including the report page.

Found by sweeping every endpoint with hostile path parameters:

    GET /api/result/%00                  500
    GET /api/jobs/%00/export.json        500
    GET /api/jobs/%00/export.stix        500
    GET /api/jobs/%00/export.pdf         500
    GET /api/jobs/%00/export.signed      500
    GET /api/jobs/%00/export.incident    500

Same class as the `/api/audit` filters, and the same class this codebase already
carries a note about: "`?status=%00` was a live 500 that every test passed
through". PostgreSQL's driver raises `ValueError` on a NUL inside a text
parameter, and the value went from the URL into a WHERE clause untouched. The
audit filters were given a `Query(pattern=...)`; the path parameter never was.

`public_id` is `str(uuid.uuid4())`, so the guard is not a sanitiser bolted on the
front — it is the truth about the column. Anything that is not a UUID cannot
match a row, so it 404s without a query.
"""
from __future__ import annotations

import uuid

import pytest

from app.api.sandbox import looks_like_public_id

#: Every shape a caller can put in the path. None can name a job.
IMPOSSIBLE = [
    "", " ", "%00", "\x00", "a" * 4000, "../../etc/passwd", "..\\..\\windows",
    "'; DROP TABLE sandbox_jobs; --", "<script>alert(1)</script>",
    "-1", "0", "99999999999999999999", "NaN", "null", "şifrə", "\U0001f642",
    "not-a-uuid", "12345678-1234-1234-1234", "{{7*7}}", "*", "%",
]

#: Routes that take a job id. `_job_or_404` funnels the sandbox ones; the two
#: worker-seam lookups in dynamic.py run their own query and are guarded there.
ROUTES = [
    "/api/result/{}",
    "/api/jobs/{}",
    "/api/jobs/{}/export.json",
    "/api/jobs/{}/export.stix",
    "/api/jobs/{}/export.pdf",
    "/api/jobs/{}/export.signed",
    "/api/jobs/{}/export.incident",
]


@pytest.mark.parametrize("value", IMPOSSIBLE)
def test_the_guard_rejects_what_cannot_be_an_id(value) -> None:
    assert looks_like_public_id(value) is False, value


def test_a_real_uuid_passes() -> None:
    assert looks_like_public_id(str(uuid.uuid4())) is True


def test_a_uuid_with_a_nul_glued_on_does_not() -> None:
    """The interesting near-miss: valid prefix, hostile tail."""
    assert looks_like_public_id(str(uuid.uuid4()) + "\x00") is False


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("value", ["%00", "a" * 4000, "not-a-uuid", "../../etc/passwd"])
def test_no_route_returns_500(client, auth, route, value) -> None:
    """The finding, end to end. 404 or 422 — never a crash."""
    response = client.get(route.format(value), headers=auth)
    assert response.status_code < 500, (route, value, response.status_code)


@pytest.mark.parametrize("route", ROUTES)
def test_a_well_formed_but_unknown_id_is_still_404(client, auth, route) -> None:
    """The guard must not have changed the ordinary miss."""
    response = client.get(route.format(str(uuid.uuid4())), headers=auth)
    assert response.status_code == 404, (route, response.status_code)


def test_the_worker_seam_is_guarded_too(client) -> None:
    """`/api/dynamic/*` runs its own lookup and never used `_job_or_404`."""
    import inspect

    from app.api import dynamic

    source = inspect.getsource(dynamic)
    assert source.count("looks_like_public_id(public_id)") == 2, (
        "both worker-seam lookups must be guarded"
    )
