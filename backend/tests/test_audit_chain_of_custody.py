"""The chain of custody has to survive being attacked, not just being written.

A log that only proves what it says when nobody tampered with it proves nothing.
These tests therefore do the tampering: they edit a stored event, and they delete
one, and they require ``verify_chain()`` to name the row. The rest pin the two
properties an evidence store cannot get wrong — the analyst's password is never
in it, and reading it takes more than a pipeline's API key.

The chain tests run against their own throwaway SQLite file, because breaking a
chain is permanent and the suite's shared database is verified clean elsewhere
in this file.
"""
from __future__ import annotations

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from app import audit
from app import db as app_db
from app.main import app


@pytest.fixture()
def chain(tmp_path, monkeypatch):
    """``(engine, sessionmaker)`` for an isolated audit table.

    ``audit.record()`` opens its own session through ``app.db.session_scope``,
    which resolves ``SessionLocal`` at call time — swapping it here redirects
    every write in the test at this file and nowhere near the suite's database.
    """
    url = "sqlite:///" + str(tmp_path / "audit.db").replace("\\", "/")
    engine = sa.create_engine(url, connect_args={"check_same_thread": False}, future=True)
    audit.AuditEvent.__table__.create(engine)
    maker = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(app_db, "SessionLocal", maker)
    try:
        yield engine, maker
    finally:
        engine.dispose()


def _series(count: int = 4) -> None:
    for index in range(count):
        audit.record(
            action=audit.AuditAction.SAMPLE_SUBMITTED,
            actor="analyst",
            actor_method="session",
            object_type="job",
            object_id=f"job-{index}",
            source_ip="10.0.0.5",
            detail={"original_name": f"sample-{index}.exe"},
        )


def _verify(maker) -> dict:
    """Verify on a fresh session: a stale identity map would hide a raw UPDATE."""
    session = maker()
    try:
        return audit.verify_chain(session)
    finally:
        session.close()


# --- the chain ---------------------------------------------------------------
def test_chain_verifies_clean_after_a_series_of_actions(chain):
    _engine, maker = chain
    audit.record(
        action=audit.AuditAction.LOGIN_SUCCESS, actor="analyst", actor_method="session"
    )
    _series()
    audit.record(
        action=audit.AuditAction.REPORT_EXPORTED,
        actor="analyst",
        actor_method="session",
        object_type="job",
        object_id="job-1",
        detail={"format": "pdf"},
    )

    report = _verify(maker)
    assert report["ok"] is True, report
    assert report["entries_checked"] == 6
    assert report["broken_at"] is None
    assert report["head_hash"] != audit.GENESIS_HASH


def test_first_entry_chains_from_the_genesis_hash(chain):
    _engine, maker = chain
    event = audit.record(
        action=audit.AuditAction.LOGIN_SUCCESS, actor="analyst", actor_method="session"
    )
    assert event is not None
    assert event.prev_hash == audit.GENESIS_HASH
    assert _verify(maker)["ok"] is True


def test_editing_a_row_in_the_database_is_detected(chain):
    engine, maker = chain
    _series()
    assert _verify(maker)["ok"] is True

    # The tamper an insider would actually attempt: rewrite who did it.
    with engine.begin() as connection:
        connection.execute(sa.text("UPDATE audit_events SET actor = 'someone_else' WHERE id = 2"))

    report = _verify(maker)
    assert report["ok"] is False
    assert report["broken_at"] == 2
    assert "modified" in report["reason"]


def test_editing_the_detail_payload_is_detected(chain):
    engine, maker = chain
    _series()
    with engine.begin() as connection:
        connection.execute(
            sa.text("UPDATE audit_events SET detail = '{\"original_name\": \"clean.txt\"}' WHERE id = 3")
        )

    report = _verify(maker)
    assert report["ok"] is False
    assert report["broken_at"] == 3


def test_deleting_a_row_is_detected(chain):
    engine, maker = chain
    _series()
    with engine.begin() as connection:
        connection.execute(sa.text("DELETE FROM audit_events WHERE id = 2"))

    report = _verify(maker)
    assert report["ok"] is False
    # The gap shows up at the row that used to follow the deleted one.
    assert report["broken_at"] == 3
    assert "deleted" in report["reason"]


def test_an_empty_chain_verifies_at_the_genesis_hash(chain):
    _engine, maker = chain
    report = _verify(maker)
    assert report["ok"] is True
    assert report["entries_checked"] == 0
    assert report["head_hash"] == audit.GENESIS_HASH


# --- secrets -----------------------------------------------------------------
def test_an_archive_password_is_never_persisted(chain, tmp_path):
    engine, maker = chain
    event = audit.record(
        action=audit.AuditAction.ARCHIVE_PASSWORD_SUPPLIED,
        actor="analyst",
        actor_method="session",
        object_type="job",
        object_id="job-locked",
        # A call site handing the real secret through is the mistake this guards.
        detail={"password": "infected-2026", "password_supplied": True},
    )
    assert event is not None
    assert event.detail["password"] == audit.REDACTED
    # The auditable fact survives; only the secret does not.
    assert event.detail["password_supplied"] is True

    with engine.connect() as connection:
        stored = connection.execute(sa.text("SELECT detail FROM audit_events")).scalars().all()
    assert not any("infected-2026" in row for row in stored)
    assert b"infected-2026" not in (tmp_path / "audit.db").read_bytes()

    assert _verify(maker)["ok"] is True


@pytest.mark.parametrize(
    "key", ["password", "Passphrase", "api_key", "auth_token", "AUTHORIZATION"]
)
def test_every_credential_shaped_key_is_redacted(chain, key):
    event = audit.record(
        action=audit.AuditAction.SAMPLE_SUBMITTED,
        actor="analyst",
        actor_method="session",
        detail={key: "s3cr3t-value"},
    )
    assert event is not None
    assert event.detail[key] == audit.REDACTED


# --- failure posture ---------------------------------------------------------
def test_a_failed_audit_write_returns_none_instead_of_raising(chain, monkeypatch, caplog):
    def boom():
        raise sa.exc.OperationalError("SELECT 1", {}, Exception("disk full"))

    monkeypatch.setattr(audit, "session_scope", boom)
    with caplog.at_level("ERROR"):
        assert (
            audit.record(
                action=audit.AuditAction.LOGIN_SUCCESS, actor="analyst", actor_method="session"
            )
            is None
        )
    # Loud: a hole in the chain of custody must not be discoverable only later.
    assert "AUDIT WRITE FAILED" in caplog.text


def test_a_failed_audit_write_does_not_fail_the_login(client, monkeypatch):
    def boom():
        raise RuntimeError("audit storage unavailable")

    monkeypatch.setattr(audit, "session_scope", boom)
    response = client.post(
        "/api/auth/login", json={"username": "analyst", "password": "analyst"}
    )
    assert response.status_code == 200, response.text


# --- the call sites ----------------------------------------------------------
def test_login_success_and_failure_are_both_recorded(client, auth):
    bogus = "intruder-probe"
    failed = client.post("/api/auth/login", json={"username": bogus, "password": "wrong"})
    assert failed.status_code == 401

    listing = client.get("/api/audit", params={"actor": bogus}, headers=auth)
    assert listing.status_code == 200, listing.text
    items = listing.json()["items"]
    assert [i["action"] for i in items] == [audit.AuditAction.LOGIN_FAILURE]
    assert items[0]["outcome"] == "failure"
    # The submitted password is not anywhere in the record of the attempt.
    assert "wrong" not in str(items[0])

    successes = client.get(
        "/api/audit", params={"action": audit.AuditAction.LOGIN_SUCCESS}, headers=auth
    )
    assert successes.json()["total"] >= 1


def test_a_scoring_weight_change_is_recorded_with_before_and_after(client, auth):
    response = client.put("/api/admin/weights", json={"rule_weight": 7, "ai_weight": 3}, headers=auth)
    assert response.status_code == 200, response.text

    listing = client.get(
        "/api/audit",
        params={"action": audit.AuditAction.SCORING_WEIGHTS_CHANGED, "object_id": "global"},
        headers=auth,
    )
    entry = listing.json()["items"][-1]
    assert entry["detail"]["rule_after"] == 0.7
    assert entry["detail"]["rule_before"] == 0.6
    assert entry["actor_method"] == "session"


def test_a_rejected_weight_change_is_recorded_as_a_failure(client, auth):
    assert client.put(
        "/api/admin/weights", json={"rule_weight": 0, "ai_weight": 0}, headers=auth
    ).status_code == 422

    listing = client.get(
        "/api/audit",
        params={"action": audit.AuditAction.SCORING_WEIGHTS_CHANGED},
        headers=auth,
    )
    assert listing.json()["items"][-1]["outcome"] == "failure"


# --- the API -----------------------------------------------------------------
@pytest.mark.parametrize("path", ["/api/audit", "/api/audit/verify", "/api/audit/export"])
def test_the_audit_router_rejects_an_api_key_and_anonymous_callers(client, path):
    assert client.get(path).status_code == 401
    # A static key pasted into a pipeline must not be able to read who did what.
    assert client.get(path, headers={"X-API-Key": "demo-key"}).status_code == 403


def test_no_route_can_modify_the_audit_trail():
    """Append-only is the absence of a route, not a rule someone remembers."""
    methods = set()
    for route in app.routes:
        path = getattr(route, "path", "")
        if path.startswith("/api/audit"):
            methods |= set(getattr(route, "methods", set()))
    assert methods <= {"GET", "HEAD"}, methods


def test_the_suite_chain_verifies_over_the_http_endpoint(client, auth):
    report = client.get("/api/audit/verify", headers=auth)
    assert report.status_code == 200
    body = report.json()
    assert body["ok"] is True, body
    assert body["entries_checked"] >= 1
    assert len(body["head_hash"]) == 64


def test_listing_is_paginated_and_filterable(client, auth):
    for _ in range(3):
        client.post("/api/auth/login", json={"username": "analyst", "password": "analyst"})

    first = client.get(
        "/api/audit",
        params={"action": audit.AuditAction.LOGIN_SUCCESS, "limit": 1, "offset": 0},
        headers=auth,
    ).json()
    second = client.get(
        "/api/audit",
        params={"action": audit.AuditAction.LOGIN_SUCCESS, "limit": 1, "offset": 1},
        headers=auth,
    ).json()

    assert len(first["items"]) == 1
    assert first["total"] == second["total"] >= 2
    assert first["items"][0]["id"] != second["items"][0]["id"]
    assert client.get("/api/audit", params={"limit": 0}, headers=auth).status_code == 422


def test_json_export_carries_the_hashes(client, auth):
    body = client.get("/api/audit/export", params={"format": "json", "limit": 5}, headers=auth).json()
    assert body["count"] >= 1
    entry = body["items"][0]
    assert len(entry["entry_hash"]) == 64
    assert len(entry["prev_hash"]) == 64


def test_cef_export_is_one_arcsight_line_per_event(client, auth):
    response = client.get(
        "/api/audit/export",
        params={"format": "cef", "action": audit.AuditAction.LOGIN_SUCCESS, "limit": 3},
        headers=auth,
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    lines = [line for line in response.text.splitlines() if line]
    assert lines
    for line in lines:
        header = line.split("|")
        assert header[0] == "CEF:0"
        assert header[1] == "Cyclowareness"
        assert header[2] == "Cyclowareness Sandbox"
        assert header[4] == audit.AuditAction.LOGIN_SUCCESS
        assert "suser=analyst" in line
        assert "cs4Label=entryHash" in line


def test_cef_escapes_a_pipe_in_attacker_controlled_detail(chain):
    """A filename is attacker text; an unescaped one would forge a CEF field."""
    event = audit.record(
        action=audit.AuditAction.SAMPLE_SUBMITTED,
        actor="analyst",
        actor_method="session",
        detail={"original_name": "in|voice=2026.exe"},
    )
    line = audit.to_cef(event, product_version="1.0.0")
    assert line.split("|")[0] == "CEF:0"
    # The '=' inside the value is escaped, so it cannot open a new extension key.
    assert "\\=2026" in line


def test_an_unknown_export_format_is_refused(client, auth):
    assert client.get(
        "/api/audit/export", params={"format": "xml"}, headers=auth
    ).status_code == 422
