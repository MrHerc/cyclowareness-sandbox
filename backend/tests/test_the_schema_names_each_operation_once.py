"""The published schema shipped `health_api_health_get` twice.

`@router.api_route("/api/health", methods=["GET", "HEAD"])` is ONE route with two
methods, and FastAPI derives a single operation id for it. The schema therefore
carried the same operationId under both `get` and `head`, which every client
generator treats as a collision -- openapi-generator, orval and openapi-typescript
all either fail or silently drop one. For a product whose whole pitch is that a
customer can drive it from their own SOAR, a schema that will not generate is a
real defect, and it announced itself as a UserWarning that the suite printed on
every run and nothing asserted on.

The check is written over the whole schema rather than over `/api/health`,
because the next route that needs GET and HEAD would reintroduce it.
"""
from __future__ import annotations

import collections

#: The methods OpenAPI describes as operations. `parameters` and `servers` are
#: also legal keys under a path item and are not operations.
OPERATIONS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


def _schema(client, auth) -> dict:
    # `/api/openapi.json`, not `/openapi.json`: the schema was deliberately moved
    # behind authentication. See `test_the_api_surface_is_not_public.py`.
    response = client.get("/api/openapi.json", headers=auth)
    assert response.status_code == 200, response.text
    return response.json()


def test_no_operation_id_is_used_twice(client, auth) -> None:
    seen = collections.Counter()
    for path, item in _schema(client, auth)["paths"].items():
        for method, operation in item.items():
            if method.lower() in OPERATIONS and "operationId" in operation:
                seen[operation["operationId"]] += 1
    duplicates = {name: n for name, n in seen.items() if n > 1}
    assert not duplicates, f"operationId used more than once: {duplicates}"


def test_every_operation_has_an_id(client, auth) -> None:
    """A generator needs a name for each one; an absent id is generated badly."""
    missing = [
        f"{method.upper()} {path}"
        for path, item in _schema(client, auth)["paths"].items()
        for method, operation in item.items()
        if method.lower() in OPERATIONS and not operation.get("operationId")
    ]
    assert not missing, missing


def test_health_is_still_reachable_both_ways(client) -> None:
    """The split must not have cost the HEAD probe its route.

    HEAD exists because uptime probes and load balancers send it and FastAPI
    does not add it to a GET route, so they were getting 405.
    """
    assert client.get("/api/health").status_code in (200, 503)
    assert client.head("/api/health").status_code in (200, 503)


def test_health_still_needs_no_credentials(client) -> None:
    """An orchestrator has to be able to call it."""
    assert client.get("/api/health").status_code != 401
