"""
auth/dependencies.py
---------------------
FastAPI authentication dependencies for the AV management API.

Architecture (fastapi-backend-skill):
  * Auth enforced via Depends() at the router level, not duplicated
    per-endpoint.
  * Two auth paths:
    - `verify_agent_key`: bcrypt-based API key for daemon ↔ backend comms
      (existing pattern from main.py, centralised here)
    - `verify_dashboard_token`: JWT-based token for dashboard UI access
  * Never log raw API keys or token payloads (fastapi-backend-skill security).
  * Generic error messages to clients; detailed errors logged server-side.

Secrets live in environment variables → settings (no hardcoded values).
"""

from __future__ import annotations

import time
from typing import Optional

import bcrypt
import jwt
import structlog
from fastapi import Depends, Header, HTTPException, Request, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from backend.core.config import settings

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Agent API key auth (daemon ↔ backend)
# ---------------------------------------------------------------------------

_api_key_scheme = APIKeyHeader(name="X-Agent-Key", auto_error=True)


def verify_agent_key(
    request: Request,
    api_key: str = Security(_api_key_scheme),
    agent_id: str = Header(..., alias="X-Agent-ID"),
) -> str:
    """
    Verify the daemon's API key using bcrypt against the hash stored in
    settings.AGENT_API_HASH.  Sets request.state.agent_id for downstream
    audit logging.

    Returns the validated agent_id on success.
    """
    try:
        is_valid = bcrypt.checkpw(
            api_key.encode("utf-8"),
            settings.AGENT_API_HASH.encode("utf-8"),
        )
        if not is_valid:
            raise ValueError("bcrypt mismatch")
    except Exception:
        # Log warning with agent_id but NEVER log the raw api_key
        logger.warning("unauthorized_agent_key_attempt", agent_id=agent_id)
        raise HTTPException(
            status_code=401,
            detail={"message": "Unauthorized agent"},
        )

    request.state.agent_id = agent_id
    return agent_id


# ---------------------------------------------------------------------------
# Dashboard JWT auth (human operators via UI)
# ---------------------------------------------------------------------------

_bearer_scheme = HTTPBearer(auto_error=True)


def verify_dashboard_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(_bearer_scheme),
) -> dict:
    """
    Validate a signed JWT for dashboard users.

    Token must be signed with settings.JWT_SECRET (HS256).
    Sets request.state.agent_id to the token's 'sub' claim for audit logging.

    Returns the decoded JWT payload on success.
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=["HS256"],
            options={"require": ["sub", "exp"]},
        )
    except jwt.ExpiredSignatureError:
        # Do NOT reveal internal details in the error message
        logger.info("jwt_token_expired")
        raise HTTPException(status_code=401, detail={"message": "Token expired"})
    except jwt.InvalidTokenError:
        logger.warning("jwt_token_invalid")
        raise HTTPException(status_code=401, detail={"message": "Invalid token"})

    request.state.agent_id = payload.get("sub", "unknown")
    return payload
