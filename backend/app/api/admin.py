"""Admin: the small set of levers the brief asks to expose for tuning.

Right now that is the rule/model aggregation split. In-memory: an override lasts
for the running process. A restart returns to the 0.6/0.4 default, which for a
tuning knob is the safe direction to fail.

These levers are global — one caller re-weights every other caller's verdicts —
so they take ``require_admin``, not ``require_analyst``: a static API key issued
for submission must not reach them.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import audit, retention
from ..auth import Identity, require_admin
from ..db import get_db
from ..engine import scoring
from ..schemas import WeightsUpdate

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/weights")
def get_weights(identity: Identity = Depends(require_admin)):
    return scoring.get_weights()


@router.put("/weights")
def set_weights(
    payload: WeightsUpdate,
    request: Request,
    identity: Identity = Depends(require_admin),
):
    current = scoring.get_weights()
    rule = payload.rule_weight if payload.rule_weight is not None else current["rule"]
    model = payload.ai_weight if payload.ai_weight is not None else current["model"]
    try:
        updated = scoring.set_weights(rule, model)
    except ValueError as exc:
        # A rejected change is still an attempt to re-weight every verdict this
        # deployment issues, and "who kept trying" is a question the trail has
        # to answer. Recorded before the 422 leaves.
        _audit_weights(request, identity, current, {"rule": rule, "model": model}, ok=False)
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    _audit_weights(request, identity, current, updated, ok=True)
    return updated


@router.post("/weights/reset")
def reset_weights(request: Request, identity: Identity = Depends(require_admin)):
    current = scoring.get_weights()
    restored = scoring.reset_weights()
    _audit_weights(request, identity, current, restored, ok=True)
    return restored


@router.get("/retention")
def get_retention(identity: Identity = Depends(require_admin)):
    """The configured data-lifecycle policy, in the words a DPA needs."""
    return retention.policy()


@router.post("/retention/run")
def run_retention(
    request: Request,
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_admin),
):
    """Sweep now rather than waiting for the scheduler.

    Operators need this for two real situations: proving to an auditor that the
    policy does what the document says, and reclaiming disk immediately after
    shortening the window. Each deletion writes its own line to the chain of
    custody, so an on-demand sweep is as accountable as a scheduled one.
    """
    outcome = retention.sweep(db, actor=identity.subject)
    return outcome.to_dict()


def _audit_weights(
    request: Request, identity: Identity, before: dict, after: dict, *, ok: bool
) -> None:
    """Record a change to the scoring split.

    Before and after both go in: a verdict is only defensible if the weights it
    was produced under can be reconstructed, and these levers are in-memory —
    the chain of custody is the only place their history exists.
    """
    audit.record(
        action=audit.AuditAction.SCORING_WEIGHTS_CHANGED,
        actor=identity.subject,
        actor_method=identity.method,
        tenant=identity.tenant,
        object_type="scoring_weights",
        object_id="global",
        source_ip=request.client.host if request.client else None,
        outcome=audit.AuditOutcome.SUCCESS if ok else audit.AuditOutcome.FAILURE,
        detail={
            "rule_before": before.get("rule"),
            "model_before": before.get("model"),
            "rule_after": after.get("rule"),
            "model_after": after.get("model"),
        },
    )
