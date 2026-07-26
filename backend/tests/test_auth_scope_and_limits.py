"""Regressions for four defects an adversarial audit reproduced against the API.

Each test here failed before the corresponding fix: a non-ASCII credential
crashed the request instead of being rejected, ``?limit=-1`` dumped the whole
jobs table, a submit-only API key could re-weight scoring for every user, and a
production boot accepted the built-in demo key.
"""
from __future__ import annotations

from app.auth import verify_login
from app.config import Settings

#: An Azerbaijani password is the founder's own first test case; every character
#: past U+007F used to make login return 500 forever.
_AZ_PASSWORD = "Şəfər-Parolu-2026"


# --- non-ASCII credentials ----------------------------------------------------
def test_non_ascii_api_key_is_rejected_not_a_crash(client):
    # A single 0xE9 byte in the header used to raise TypeError out of
    # hmac.compare_digest, so an unauthenticated caller could force a 500.
    # Sent as raw bytes because the header value is not ASCII by design.
    response = client.post(
        "/api/analyze",
        files={"file": ("note.txt", b"hi", "text/plain")},
        headers={"X-API-Key": b"\xe9"},
    )
    assert response.status_code == 401


def test_non_ascii_password_is_rejected_not_a_crash(client):
    response = client.post(
        "/api/auth/login", json={"username": "analyst", "password": _AZ_PASSWORD}
    )
    assert response.status_code == 401


def test_non_ascii_credentials_can_actually_authenticate():
    # The other half of the bug: with a non-ASCII ANALYST_PASSWORD configured,
    # even the correct password could never be accepted.
    settings = Settings(analyst_username="şəfər", analyst_password=_AZ_PASSWORD)
    assert verify_login("şəfər", _AZ_PASSWORD, settings) is True
    assert verify_login("şəfər", _AZ_PASSWORD + "x", settings) is False
    assert verify_login("analyst", _AZ_PASSWORD, settings) is False


def test_non_ascii_session_token_is_rejected_not_a_crash(client):
    response = client.get("/api/jobs", headers={"Authorization": b"Bearer \xe9.\xe9"})
    assert response.status_code == 401


# --- the limit cap ------------------------------------------------------------
def test_negative_limit_cannot_defeat_the_cap(client, auth):
    # min(-1, 200) == -1, and SQLite treats LIMIT -1 as unbounded.
    assert client.get("/api/jobs?limit=-1", headers=auth).status_code == 422
    assert client.get("/api/jobs?limit=0", headers=auth).status_code == 422
    assert client.get("/api/jobs?limit=100000", headers=auth).status_code == 422


def test_limit_within_range_still_works(client, auth):
    for value in (1, 50, 200):
        response = client.get(f"/api/jobs?limit={value}", headers=auth)
        assert response.status_code == 200, response.text
        assert len(response.json()) <= value


# --- admin scope --------------------------------------------------------------
def test_api_key_cannot_reach_admin_routes(client, auth):
    before = client.get("/api/admin/weights", headers=auth).json()

    key = {"X-API-Key": "demo-key"}
    body = {"rule_weight": 9.0, "ai_weight": 1.0}
    for label, response in (
        ("GET weights", client.get("/api/admin/weights", headers=key)),
        ("PUT weights", client.put("/api/admin/weights", json=body, headers=key)),
        ("POST reset", client.post("/api/admin/weights/reset", headers=key)),
    ):
        assert response.status_code == 403, f"{label}: {response.text}"

    assert client.get("/api/admin/weights", headers=auth).json() == before


def test_analyst_session_still_reaches_admin_routes(client, auth):
    assert client.get("/api/admin/weights", headers=auth).status_code == 200
    updated = client.put(
        "/api/admin/weights", json={"rule_weight": 3.0, "ai_weight": 1.0}, headers=auth
    )
    assert updated.status_code == 200, updated.text
    assert client.post("/api/admin/weights/reset", headers=auth).status_code == 200


# --- production configuration -------------------------------------------------
def _production_settings(**overrides) -> Settings:
    base = {
        "app_env": "production",
        "secret_key": "a-real-32-byte-or-longer-secret-key",
        "analyst_password": "a-real-analyst-password",
        "database_url": "postgresql://sandbox@db/sandbox",
        "api_keys": "b8f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
    }
    base.update(overrides)
    return Settings(**base)


def test_production_refuses_the_built_in_api_key():
    problems = _production_settings(api_keys="demo-key").validate_production()
    assert any("API_KEYS" in p for p in problems), problems

    # Also caught when it is one entry among several real keys.
    mixed = _production_settings(api_keys="b8f1c2d3e4f5a6b7,demo-key").validate_production()
    assert any("API_KEYS" in p for p in mixed), mixed


def test_production_accepts_a_fully_hardened_configuration():
    assert _production_settings().validate_production() == []
