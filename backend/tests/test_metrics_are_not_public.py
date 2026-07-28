"""`/metrics` publishes a customer's business, and nobody has to log in.

The counters are how many samples this deployment took, how many were malicious,
how many uploads were rejected and how long analysis takes. Served openly they
tell a competitor a customer's volume and threat profile from an endpoint that
needs no credential — so nobody ever notices it being read, either.

Closed by default in production, opened deliberately: a bearer token for the
scraper, or `METRICS_PUBLIC=true` to say out loud that this deployment intends
anyone to read them. Not the analyst session — a Prometheus scraper cannot log
in, and a metrics endpoint that needs a browser never gets scraped.

The demo build leaves them open, because it is a thing someone runs on a laptop
to look at and this is one of the things worth looking at.
"""
from __future__ import annotations

import pytest

from app.config import get_settings


@pytest.fixture()
def production(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "metrics_public", False)
    monkeypatch.setattr(settings, "metrics_token", "")
    return settings


def test_the_demo_build_leaves_them_open(client) -> None:
    assert get_settings().is_demo
    assert client.get("/metrics").status_code == 200


def test_production_closes_them_by_default(client, production) -> None:
    response = client.get("/metrics")
    assert response.status_code == 404, response.status_code
    assert "detail" in response.json()


def test_a_token_opens_them(client, production, monkeypatch) -> None:
    monkeypatch.setattr(production, "metrics_token", "scrape-me-please")
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"Authorization": "wrong"}).status_code == 401
    assert client.get(
        "/metrics", headers={"Authorization": "Bearer scrape-me-please"}
    ).status_code == 200
    assert client.get(
        "/metrics", headers={"Authorization": "scrape-me-please"}
    ).status_code == 200


def test_saying_so_out_loud_opens_them(client, production, monkeypatch) -> None:
    monkeypatch.setattr(production, "metrics_public", True)
    assert client.get("/metrics").status_code == 200


def test_an_analyst_session_is_not_the_answer(client, auth, production) -> None:
    """A scraper has no session. If this ever starts passing, the endpoint has
    been made unscrapeable rather than protected."""
    assert client.get("/metrics", headers=auth).status_code == 404
