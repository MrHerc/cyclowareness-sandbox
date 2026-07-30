"""The chain of custody, read-only.

Three routes, and deliberately no fourth: there is no PUT, PATCH, POST or DELETE
anywhere in this module. Append-only is not a policy an operator is trusted to
follow here — it is the absence of a route. The only writer is
``app.audit.record()``, called from the actions themselves.

Everything here is ``require_admin``: the audit trail names who submitted which
sample from which address, so reading it is itself a privileged act, and a
static API key pasted into a CI pipeline must not be able to do it.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from .. import __version__, audit
from ..auth import Identity, require_admin
from ..db import get_db
from ..schemas import MAX_OFFSET

router = APIRouter(prefix="/api/audit", tags=["audit"])

#: The four free-text filters, bounded and made printable.
#:
#: They were plain `str | None` and went straight into a SQL comparison. On
#: PostgreSQL a NUL byte in a text parameter is a `ValueError` from the driver
#: — an authenticated 500 on the audit trail from `?actor=%00` — and an
#: unbounded string is a query parameter the caller sizes. The columns they
#: filter are 128 chars or less, so nothing longer can match anything anyway.
#:
#: 128 printable ASCII, matching the widest of the columns (`actor`).
#:
#: A FUNCTION, not a shared `Query()` instance. FastAPI binds the parameter's
#: name onto the object it is given, so one instance reused across four
#: parameters ends up with one alias and all four read the same query key —
#: `?actor=x` was silently ignored and every filtered request returned the
#: unfiltered set.
def _filter() -> Any:
    return Query(default=None, max_length=128, pattern=r"^[ -~]*$")




@router.get("")
def list_events(
    actor: str | None = _filter(),
    action: str | None = _filter(),
    object_type: str | None = _filter(),
    object_id: str | None = _filter(),
    # Bounded at the edge rather than clamped in the handler: a negative limit
    # reads as "unbounded" to SQLite, which would serialise the whole trail.
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=MAX_OFFSET),
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_admin),
):
    total, events = audit.query(
        db,
        actor=actor,
        action=action,
        object_type=object_type,
        object_id=object_id,
        tenant=identity.tenant,
        limit=limit,
        offset=offset,
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [event.to_dict() for event in events],
    }


@router.get("/verify")
def verify(
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_admin),
):
    """Walk the whole chain and name the first broken link, if there is one.

    Answers 200 either way: "the chain is broken at row 41" is a successful
    verification, and an auditor needs that answer in the body, not as an error.

    DEPLOYMENT-WIDE, not tenant-scoped, and that is not an oversight. The chain
    is one hash chain over every action on this deployment — that is what makes
    a deleted row detectable. Verifying only a tenant's own rows would verify a
    subsequence, which any subsequence of a valid chain trivially fails, and
    re-chaining per tenant would mean a row could be deleted from one tenant's
    chain without any other chain noticing.

    The cost is stated rather than hidden: the counts and head hash returned here
    are deployment-wide, so on a multi-tenant install they tell a caller roughly
    how much activity the other tenants generate. `require_admin` keeps that to
    an interactive session; an API key cannot reach it.
    """
    return audit.verify_chain(db)


@router.get("/export")
def export(
    format: str = Query(default="json", pattern="^(json|cef)$"),
    actor: str | None = _filter(),
    action: str | None = _filter(),
    object_type: str | None = _filter(),
    object_id: str | None = _filter(),
    limit: int = Query(default=1000, ge=1, le=10000),
    offset: int = Query(default=0, ge=0, le=MAX_OFFSET),
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_admin),
):
    """The SIEM pull. ``format=cef`` for ArcSight-compatible collectors, ``json``
    for everything else.

    Paged like the list route rather than streaming the table: a SOC poller asks
    for the window it has not seen yet, and an unbounded export is a memory
    profile an attacker can trigger with one authenticated request.
    """
    _total, events = audit.query(
        db,
        actor=actor,
        action=action,
        object_type=object_type,
        object_id=object_id,
        tenant=identity.tenant,
        limit=limit,
        offset=offset,
    )
    if format == "cef":
        body = "\n".join(audit.to_cef(e, product_version=__version__) for e in events)
        return PlainTextResponse(content=body + "\n" if body else "", media_type="text/plain")
    return {"count": len(events), "items": [event.to_dict() for event in events]}
