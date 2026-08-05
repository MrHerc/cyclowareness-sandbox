"""One byte in a username erased the failed-login record.

`audit.record` writes `actor[:128]` straight into a PostgreSQL text column, and
the driver raises on a NUL before the statement is sent. `record()` deliberately
never fails the caller's operation -- an audit table must not turn into an
outage -- so it logged at ERROR, counted the failure and returned None. The login
still failed and the attempt left NO row in the chain of custody.

That is reachable with no credential at all: `POST /api/auth/login` records the
submitted username as the actor. One byte, and a credential-guessing run is
invisible to the thing whose entire purpose is that it cannot be.

Fixed in `record()` rather than at the call site, because every column it writes
is caller-influenced somewhere. `detail` had `_sanitise` all along; the six
scalars had nothing.

Second, unrelated in mechanism and identical in kind:
`/api/sovereignty/refusals` was gated on `require_analyst`, which an API key
satisfies. Its own docstring explains that the detail is "analysis data belonging
to the deployment" -- for `url_fetch` the submitted URL verbatim, for
`virustotal` the sample's SHA-256 -- and the records carry no tenant. So one
tenant's submit-only key read what every other tenant had been analysing.
`require_admin` means an interactive session, which is the distinction
`/api/admin/*` already draws for the same reason.
"""
from __future__ import annotations

from sqlalchemy import func, select

from app import audit

NUL = chr(0)


def _count(db) -> int:
    return int(db.execute(select(func.count(audit.AuditEvent.id))).scalar_one() or 0)


# --- the chain of custody ----------------------------------------------------

def test_a_nul_in_the_actor_still_produces_a_record(db) -> None:
    """The finding. Before: the row was dropped and the caller never knew."""
    before = _count(db)
    event = audit.record(
        actor="analyst" + NUL + "x",
        actor_method="session",
        action="auth.login",
        object_type="session",
        object_id="-",
        outcome="failure",
        detail={"note": "probe"},
        tenant="default",
    )
    assert event is not None, "the attempt must be recorded"
    assert _count(db) == before + 1
    assert NUL not in (event.actor or "")


def test_every_scalar_column_is_guarded(db) -> None:
    """Not just the actor: each of these is caller-influenced somewhere."""
    event = audit.record(
        actor="a" + NUL,
        actor_method="s" + NUL,
        action="b" + NUL,
        object_type="c" + NUL,
        object_id="d" + NUL,
        outcome="failure",
        source_ip="10.0.0.1" + NUL,
        detail={},
        tenant="t" + NUL,
    )
    assert event is not None
    for field in ("actor", "actor_method", "action", "object_type",
                  "object_id", "tenant_id", "source_ip"):
        assert NUL not in (getattr(event, field) or ""), field


def test_the_record_still_chains(db) -> None:
    """A sanitised row must still hash and link like any other."""
    audit.record(actor="x" + NUL, actor_method="session", action="probe",
                 object_type="job", object_id="1", outcome="success",
                 detail={}, tenant="default")
    assert audit.verify_chain(db)["ok"] is True


def test_an_oversized_actor_is_still_clipped(db) -> None:
    """The guard replaced the slice; it must not have dropped the clipping."""
    event = audit.record(actor="a" * 500, actor_method="session", action="probe",
                         object_type="job", object_id="1", outcome="success",
                         detail={}, tenant="default")
    assert event is not None
    assert len(event.actor) == 128


# --- the cross-tenant read ---------------------------------------------------

def test_an_api_key_cannot_read_the_refusal_detail(client) -> None:
    """It carries other tenants' URLs and sample hashes, and has no tenant."""
    response = client.get("/api/sovereignty/refusals",
                          headers={"X-API-Key": "demo-key"})
    assert response.status_code == 403, response.text


def test_an_unauthenticated_caller_certainly_cannot(client) -> None:
    assert client.get("/api/sovereignty/refusals").status_code == 401


def test_the_public_tally_is_still_public(client) -> None:
    """The COUNT is the auditable claim and stays unauthenticated on purpose."""
    response = client.get("/api/capabilities/public")
    assert response.status_code == 200
    sovereignty = response.json()["sovereignty"]
    assert "recent" not in sovereignty, "the detail must not leak through here"
