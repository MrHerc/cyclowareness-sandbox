"""A health check that cannot fail is not checking anything.

`GET /api/health` returned a dict of constants. The Docker HEALTHCHECK calls it
and so does render.yaml's `healthCheckPath`, so a process that could not reach
its database — answering 500 to every real request — reported healthy to both,
indefinitely, and an orchestrator had no reason to restart or replace it.

One trivial round-trip is the difference between "the process is up" and "the
process is up and can serve".
"""
from __future__ import annotations


def test_health_reports_the_database(client) -> None:
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"


def test_health_goes_503_when_the_database_is_gone(client, monkeypatch) -> None:
    """The assertion that makes the check worth having."""
    from app.api import meta

    def _broken():
        raise RuntimeError("connection refused")

    monkeypatch.setattr(meta, "session_scope", _broken)
    response = client.get("/api/health")
    assert response.status_code == 503, response.status_code
    body = response.json()
    assert body["status"] == "degraded"
    assert body["database"] == "unreachable"


def test_head_works_because_probes_use_it(client) -> None:
    """FastAPI does not add HEAD to a GET route, so every uptime monitor and
    load balancer that probes with HEAD was getting 405 from the endpoint whose
    entire job is to answer them."""
    assert client.head("/api/health").status_code == 200
