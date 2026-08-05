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
from fastapi.responses import JSONResponse, PlainTextResponse
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
    result = audit.verify_chain(db)
    # The chain proves internal consistency. Internal consistency is what an
    # attacker with UPDATE can restore, so the answer is incomplete without
    # the signed anchors -- see `audit.verify_checkpoints`.
    result["anchor"] = audit.verify_checkpoints(db)
    if result.get("ok") and result["anchor"].get("broken_at") is not None:
        result["ok"] = False
        result["reason"] = result["anchor"]["reason"]

    # AND THE ABSENCE OF AN ANCHOR HAS TO BE VISIBLE WHERE `ok` IS.
    #
    # The line above only reacts to `broken_at`, and neither "not anchored"
    # branch of `verify_checkpoints` sets that key — a deployment with no
    # checkpoints, or with checkpoints and no public key to check them against,
    # returns `{"anchored": False, "reason": ...}` with no `broken_at` at all.
    # `.get()` yielded None, the condition was false, and the endpoint answered
    # `ok: true` for a chain with no anchor whatsoever, three lines under a
    # comment saying internal consistency is exactly what an attacker with
    # UPDATE can restore. `docs/api.md` tells an auditor this endpoint answers
    # the only question that matters about an audit log.
    #
    # `ok` still means what it has always meant — the chain links verify — and
    # it is NOT flipped here. `verify_checkpoints` documents that "not anchored"
    # and "chain broken" must not read the same, and
    # `test_an_unsigned_deployment_says_so_rather_than_passing` holds it. What
    # was missing is that a caller reading the top level had no way to learn the
    # difference without descending into `result["anchor"]`.
    result["anchored"] = bool(result["anchor"].get("anchored"))
    if not result["anchored"] and result["anchor"].get("reason"):
        result["anchor_reason"] = result["anchor"]["reason"]
    # WHO OWNS WHICH EVENT, checked against the last signed statement of it.
    #
    # `tenant_unprotected` above counts rows whose tenant is not inside their own
    # hashed detail -- 14,122 of 14,145 here, because they predate that copy.
    # This is what covers them instead: the mapping was signed into a checkpoint
    # rather than written into the rows, so it can be verified without the chain
    # ever having been rewritten. Read the two together: one says how many rows
    # the per-row check misses, the other says whether the signed mapping still
    # holds for them.
    result["attribution"] = audit.verify_attribution(db)
    return result


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
    # THE TOTAL WAS COMPUTED AND THROWN AWAY, and this is the chain of custody.
    #
    # A SIEM asking for the export got `count: 1000` out of 14,044 events with
    # nothing in the body or the headers to say a page boundary had been hit.
    # A poller that trusts `count` stops there, and the gap it leaves is
    # invisible: an audit log that is silently short is worse than one that is
    # missing, because the short one still looks complete.
    #
    # `count` keeps its meaning (rows in THIS response) so an existing consumer
    # does not change behaviour; `total`, `offset` and `has_more` are the new
    # facts. The headers carry the same three, because `format=cef` returns
    # plain text and a CEF collector has nowhere else to read them.
    remaining = max(0, total - (offset + len(events)))
    headers = {
        "X-Total-Count": str(total),
        "X-Result-Offset": str(offset),
        "X-Has-More": "true" if remaining else "false",
    }
    if format == "cef":
        body = "\n".join(audit.to_cef(e, product_version=__version__) for e in events)
        return PlainTextResponse(
            content=body + "\n" if body else "",
            media_type="text/plain",
            headers=headers,
        )
    return JSONResponse(
        content={
            "count": len(events),
            "total": total,
            "offset": offset,
            "has_more": bool(remaining),
            "items": [event.to_dict() for event in events],
        },
        headers=headers,
    )
