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
    # NOT `/api/jobs/` — that one names a route that exists and is redirected,
    # see test_a_trailing_slash_still_redirects_to_the_route_that_exists.
    "/api/nope/",
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


@pytest.mark.parametrize("method", ["TRACE", "PROPFIND", "LOCK", "MKCOL", "SEARCH"])
def test_every_method_means_every_method(client, method) -> None:
    """Enumerating verbs is how this was wrong the first time.

    The fallback listed seven, so anything outside the list fell past it into a
    framework 405 advertising `Allow: DELETE, GET, HEAD, OPTIONS, PATCH, POST,
    PUT` — seven methods that endpoint does not have, on a path that does not
    exist. It is registered with `methods=None` now, which matches all of them.
    """
    response = client.request(method, "/api/does-not-exist")
    assert response.status_code == 404, (
        f"{method} -> {response.status_code} allow={response.headers.get('allow')}"
    )


@pytest.mark.parametrize("path", ["//api/jobs", "/API/jobs", "///api/does-not-exist"])
def test_a_path_that_reads_as_api_never_answers_html(client, path) -> None:
    """A router match is exact, so `//api/jobs` is not `/api/jobs` and went
    straight to the SPA — 200 text/html for an API-shaped path, which is the
    whole bug this file is about, still reachable by anyone whose URL builder
    emits a double slash.

    In the suite there is no compiled frontend, so these 404 either way; the
    assertion that matters is the content type, which is what differs in the
    image customers actually run.
    """
    response = client.get(path)
    assert response.status_code == 404, response.status_code
    assert not response.headers["content-type"].startswith("text/html"), (
        f"{path} answered HTML"
    )


def test_a_trailing_slash_still_redirects_to_the_route_that_exists(client, auth) -> None:
    """A 307 preserves the method and the body, so `POST /api/analyze/url/`
    completed the submission. Claiming every path under /api made Starlette's
    redirect unreachable and turned it into a hard 404 that drops the body."""
    response = client.get("/api/jobs/", headers=auth, follow_redirects=False)
    assert response.status_code == 307, response.status_code
    assert response.headers["location"].endswith("/api/jobs")

    # The query string has to survive it, or paging through a trailing slash
    # silently returns page one.
    response = client.get("/api/jobs/?limit=1&offset=2", headers=auth, follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"].endswith("/api/jobs?limit=1&offset=2")

    # And a trailing slash on a path that is not a route is still a 404.
    assert client.get("/api/nope/", headers=auth).status_code == 404


def test_it_does_not_shadow_a_route_that_exists(client, auth) -> None:
    """The fallback is registered after every router, so a real path still wins.

    Both halves matter: an authenticated 200 and an unauthenticated 401. If the
    catch-all had been registered first, the second assertion is the one that
    would fail — every API route would answer 404 and the product would be gone.
    """
    assert client.get("/api/jobs", headers=auth).status_code == 200
    assert client.get("/api/jobs").status_code == 401
    assert client.get("/api/capabilities").status_code == 200
    # Not `in (200, 404)`. That is what this test exists to catch, and writing
    # the failure into the assertion permits it — `/api/health` is
    # render.yaml's healthCheckPath, so a 404 here is the deployment going
    # unhealthy, not an acceptable alternative.
    assert client.get("/api/health").status_code == 200


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
