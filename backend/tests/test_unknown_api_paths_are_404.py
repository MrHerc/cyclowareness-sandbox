"""An unknown API path is a client error, not a page.

In the Docker image — the only build customers run — the SPA fallback answered
for every path no route claimed, including everything under `/api`. Measured on
production over eight paths: `/api/does-not-exist`, `/api/analyse` (a plausible
typo for `/api/analyze`), `/api/jobs/xyz`, `/api/audit/nope`, `/api/result/a/b`
and `/api/jobs/` with a trailing slash all returned **200 text/html**, 925 bytes
of `index.html`.

`spa()`'s own docstring asserted "/api/* never reaches here — those routes are
registered above and match first", which is true only of paths that already
match a route. The ones this is about are exactly the ones that do not.

The cost was not cosmetic. `frontend/src/lib/api.ts` decides an error occurred
from the status alone, so a 200 went straight to `res.json()` on HTML and threw
a bare `SyntaxError` rather than an `ApiError` — the UI reported a parse failure
where the truth was "no such endpoint", and every 404 branch in the client
became unreachable code.

The suite runs without a compiled frontend, so `spa()` is not mounted here and
these paths would 404 anyway. That is the point of asserting the BODY and the
CONTENT TYPE rather than only the status: the guard has to make dev and the
image agree, and a test that only checks for 404 passes in dev whatever the
image does.
"""
from __future__ import annotations

import pytest

UNKNOWN = [
    "/api/does-not-exist",
    "/api/analyse",
    "/api/jobs/xyz",
    "/api/audit/nope",
    "/api/result/a/b",
    "/api/jobs/",
    "/api/",
    "/api",
    "/api/admin",
    "/api/dynamic/queue/extra",
]


@pytest.mark.parametrize("path", UNKNOWN)
def test_an_unknown_api_path_is_a_json_404(client, path) -> None:
    response = client.get(path)
    assert response.status_code == 404, f"{path} -> {response.status_code}"
    assert response.headers["content-type"].startswith("application/json"), (
        f"{path} answered {response.headers.get('content-type')}"
    )
    assert isinstance(response.json().get("detail"), str)


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_every_method_gets_the_same_answer(client, method) -> None:
    """The SPA fallback was GET-only, so an unknown path with any other verb
    produced a 405 whose Allow header advertised GET on an endpoint that does
    not exist."""
    response = getattr(client, method)("/api/does-not-exist")
    assert response.status_code == 404, f"{method.upper()} -> {response.status_code}"
    assert isinstance(response.json().get("detail"), str)


def test_it_does_not_shadow_a_route_that_exists(client, auth) -> None:
    """The fallback is registered after every router, so a real path still wins.

    Both halves matter: an authenticated 200 and an unauthenticated 401. If the
    catch-all had been registered first, the second assertion is the one that
    would fail — every API route would answer 404 and the product would be gone.
    """
    assert client.get("/api/jobs", headers=auth).status_code == 200
    assert client.get("/api/jobs").status_code == 401
    assert client.get("/api/capabilities").status_code == 200
    assert client.get("/api/health").status_code in (200, 404)


def test_a_real_path_with_the_wrong_verb_is_405_not_404(client, auth) -> None:
    """"No such endpoint" and "not with that verb" are different answers.

    FastAPI does not add HEAD to a GET route, so `HEAD /api/jobs` falls through
    to the fallback. Answering 404 there would say an endpoint the very next
    request will successfully use does not exist — and it is a regression from
    what the framework did before the fallback existed. Measured on the previous
    image: `HEAD /api/jobs` was 405.
    """
    response = client.head("/api/jobs", headers=auth)
    assert response.status_code == 405, response.status_code
    assert "GET" in response.headers.get("allow", ""), response.headers

    # POST to a GET-only route, and GET on a POST-only route.
    assert client.post("/api/jobs", headers=auth).status_code == 405
    assert client.get("/api/analyze", headers=auth).status_code == 405

    # And a path that really is not there stays 404 for every verb.
    assert client.head("/api/does-not-exist", headers=auth).status_code == 404
    assert client.post("/api/does-not-exist", headers=auth).status_code == 404


def test_an_unknown_path_does_not_leak_whether_a_job_exists(client, auth) -> None:
    """404 is already the answer for a job in another tenant. An unknown route
    must be indistinguishable from it, or the shape of the error becomes the
    oracle that returning 404 instead of 403 exists to remove."""
    real_shape = client.get("/api/result/does-not-exist", headers=auth)
    unknown_shape = client.get("/api/result/a/b/c", headers=auth)
    assert real_shape.status_code == unknown_shape.status_code == 404
    assert set(real_shape.json()) == set(unknown_shape.json()) == {"detail"}
