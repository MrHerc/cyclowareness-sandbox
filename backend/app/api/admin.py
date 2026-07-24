"""Admin: the small set of levers the brief asks to expose for tuning.

Right now that is the rule/model aggregation split. Analyst-authenticated, and
in-memory: an override lasts for the running process. A restart returns to the
0.6/0.4 default, which for a tuning knob is the safe direction to fail.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..auth import Identity, require_analyst
from ..engine import scoring
from ..schemas import WeightsUpdate

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/weights")
def get_weights(identity: Identity = Depends(require_analyst)):
    return scoring.get_weights()


@router.put("/weights")
def set_weights(payload: WeightsUpdate, identity: Identity = Depends(require_analyst)):
    current = scoring.get_weights()
    rule = payload.rule_weight if payload.rule_weight is not None else current["rule"]
    model = payload.ai_weight if payload.ai_weight is not None else current["model"]
    try:
        return scoring.set_weights(rule, model)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/weights/reset")
def reset_weights(identity: Identity = Depends(require_analyst)):
    return scoring.reset_weights()
