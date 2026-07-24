"""Login. Exchanges the configured analyst credentials for a session token."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from ..auth import issue_token, verify_login
from ..config import Settings, get_settings
from ..schemas import LoginRequest, LoginResponse

logger = logging.getLogger("sandbox.auth")

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, settings: Settings = Depends(get_settings)):
    if not verify_login(payload.username, payload.password, settings):
        # One message for both wrong-user and wrong-password: which of the two
        # failed is not the caller's business, and telling them enumerates users.
        logger.info("failed login for %r", payload.username[:64])
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    token, exp = issue_token(payload.username, settings=settings)
    return LoginResponse(token=token, expires_at=exp, subject=payload.username)
