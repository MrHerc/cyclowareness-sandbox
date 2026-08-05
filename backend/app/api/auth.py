"""Login. Exchanges the configured analyst credentials for a session token."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status

from .. import audit
from ..auth import Identity, issue_token, require_analyst, revoke_sessions, verify_login
from ..config import Settings, get_settings
from ..remote import client_ip
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
    source_ip = client_ip(request)

    if not verify_login(payload.username, payload.password, settings):
        # One message for both wrong-user and wrong-password: which of the two
        # failed is not the caller's business, and telling them enumerates users.
        logger.info("failed login for %r", attempted)
        audit.record(
            action=audit.AuditAction.LOGIN_FAILURE,
            actor=attempted,
            actor_method="session",
            # No authenticated identity exists yet, so this is filed under the
            # tenant the analyst account belongs to. A failed login is that
            # tenant's security event to see — it is their account being probed.
            tenant=settings.analyst_tenant_name,
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
        tenant=settings.analyst_tenant_name,
        source_ip=source_ip,
        detail={"expires_at": exp},
    )
    return LoginResponse(token=token, expires_at=exp, subject=payload.username)


@router.post("/logout", status_code=204)
def logout(request: Request, identity: Identity = Depends(require_analyst)):
    """End every session for this subject, server-side.

    Logging out cleared `localStorage` and nothing else, so a token that had
    already left the browser -- copied into a shared curl command, read out of a
    DOM bug, left on an unlocked workstation -- stayed valid for its full twelve
    hours with nothing able to stop it. This product renders strings lifted out
    of live malware, so that was the wrong answer to have ready.

    It revokes EVERY session for the subject, not just the presented one. There
    is a single analyst account, so "log me out" and "log out everything I am"
    are the same intent, and the narrower reading would leave a stolen token
    alive while the person who noticed thinks they have acted.

    Recorded in the chain of custody: an analyst ending a session is a fact an
    auditor reconstructing a timeline needs, and it is the one action that
    explains why a token stopped working.
    """
    epoch = revoke_sessions(identity.subject)
    audit.record(
        action=audit.AuditAction.LOGOUT,
        actor=identity.subject[:64],
        actor_method=identity.method,
        tenant=identity.tenant,
        source_ip=client_ip(request),
        detail={"sessions_revoked_through_epoch": epoch},
    )
    return None
