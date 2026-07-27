"""Login. Exchanges the configured analyst credentials for a session token."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status

from .. import audit
from ..auth import issue_token, verify_login
from ..config import Settings, get_settings
from ..schemas import LoginRequest, LoginResponse

logger = logging.getLogger("sandbox.auth")

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest, request: Request, settings: Settings = Depends(get_settings)
):
    # The attempted username, bounded. It is the only part of the submitted
    # credential that may ever reach the chain of custody, and it is
    # attacker-controlled on a failure, so it is truncated like any other
    # untrusted string. audit.record() redacts the password field regardless.
    attempted = payload.username[:64]
    source_ip = request.client.host if request.client else None

    if not verify_login(payload.username, payload.password, settings):
        # One message for both wrong-user and wrong-password: which of the two
        # failed is not the caller's business, and telling them enumerates users.
        logger.info("failed login for %r", attempted)
        audit.record(
            action=audit.AuditAction.LOGIN_FAILURE,
            actor=attempted,
            actor_method="session",
            outcome=audit.AuditOutcome.FAILURE,
            source_ip=source_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    token, exp = issue_token(payload.username, settings=settings)
    audit.record(
        action=audit.AuditAction.LOGIN_SUCCESS,
        actor=payload.username[:64],
        actor_method="session",
        source_ip=source_ip,
        detail={"expires_at": exp},
    )
    return LoginResponse(token=token, expires_at=exp, subject=payload.username)
