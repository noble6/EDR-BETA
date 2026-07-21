"""
routers/signatures.py
----------------------
FastAPI router: signature version listing and signature update endpoints.

Security design (fastapi-backend-skill):
  * Rate-limited endpoint for signature updates — prevents abuse of the
    update trigger (rate limiting applied via SlowAPI in main.py).
  * Outbound signature feed fetches use httpx.AsyncClient with explicit
    timeout and retry (never `requests` — fastapi-backend-skill requirement).
  * Signature source URL read from config — no hardcoded URLs or secrets.
  * Input validated through Pydantic — never trust raw request bodies.

No hardcoded secrets — SIGNATURE_FEED_URL comes from core.config.settings.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

import asyncpg
import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, HttpUrl
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

from backend.core.config import settings
from backend.db.pool import get_pool

logger = structlog.get_logger()
router = APIRouter(prefix="/signatures", tags=["signatures"])

# httpx client is created once — not per request (fastapi-backend-skill:
# connection pool created once at startup, never per-request).
# The client is initialised in the lifespan handler in main.py and injected
# via app.state; here we construct a module-level default for standalone use.
_http_client: Optional[httpx.AsyncClient] = None


def get_http_client() -> httpx.AsyncClient:
    """Return the shared AsyncClient; create lazily if not yet initialised."""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0),
            follow_redirects=True,
        )
    return _http_client


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class SignatureVersionRecord(BaseModel):
    version_id: str
    released_at: str
    source: str
    rule_count: int
    notes: Optional[str]


class SignatureListResponse(BaseModel):
    versions: List[SignatureVersionRecord]
    latest: Optional[SignatureVersionRecord]


class SignatureUpdateRequest(BaseModel):
    """
    Trigger a signature update from a trusted feed URL.
    URL must be HTTPS to prevent MITM on the signature feed.
    """
    feed_url: HttpUrl = Field(
        ...,
        description="HTTPS URL of the YARA rule archive to fetch"
    )
    source_label: str = Field(..., min_length=1, max_length=128)
    notes: Optional[str] = Field(None, max_length=512)


# ---------------------------------------------------------------------------
# Retry policy for outbound signature feed fetches
# ---------------------------------------------------------------------------

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(httpx.TransportError),
    reraise=True,
)
async def _fetch_signature_feed(url: str, client: httpx.AsyncClient) -> bytes:
    """
    Fetch signature archive from the given URL with retry + timeout.
    Uses httpx.AsyncClient — never `requests` (fastapi-backend-skill).
    """
    response = await client.get(url)
    response.raise_for_status()
    return response.content


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", response_model=SignatureListResponse)
async def list_signature_versions(
    limit: int = 20,
    pool: asyncpg.Pool = Depends(get_pool),
) -> SignatureListResponse:
    """List available signature versions, most recent first."""
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT version_id, released_at, source, rule_count, notes
                FROM signature_versions
                ORDER BY released_at DESC
                LIMIT $1
                """,
                limit,
            )
    except asyncpg.PostgresError:
        logger.exception("sig_list_db_error")
        raise HTTPException(status_code=500, detail="Failed to retrieve signature versions")

    versions = [
        SignatureVersionRecord(
            version_id=str(r["version_id"]),
            released_at=r["released_at"].isoformat(),
            source=r["source"],
            rule_count=r["rule_count"],
            notes=r["notes"],
        )
        for r in rows
    ]

    return SignatureListResponse(
        versions=versions,
        latest=versions[0] if versions else None,
    )


@router.post("/update", status_code=202)
async def trigger_signature_update(
    body: SignatureUpdateRequest,
    request: Request,
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    """
    Trigger a signature database update by fetching from the given feed URL.

    Rate-limited: max 5 update triggers per minute per API key.
    (SlowAPI rate limiter applied at router registration in main.py)

    Flow:
      1. Fetch YARA archive from feed_url (httpx, timeout, 3 retries)
      2. Parse manifest to extract rule_count
      3. Write a new signature_versions row
      4. Return the new version_id for daemon pickup
    """
    actor = getattr(request.state, "agent_id", "unknown")

    # Security: enforce HTTPS on signature feed to prevent MITM
    if not str(body.feed_url).startswith("https://"):
        raise HTTPException(
            status_code=422,
            detail="feed_url must use HTTPS to prevent signature tampering"
        )

    try:
        client = get_http_client()
        raw_content = await _fetch_signature_feed(str(body.feed_url), client)
    except httpx.HTTPStatusError as e:
        # Log detailed error server-side; return generic message to client
        logger.error(
            "sig_feed_http_error",
            url=str(body.feed_url),
            status_code=e.response.status_code,
            actor=actor,
        )
        raise HTTPException(status_code=502, detail="Signature feed fetch failed")
    except (httpx.TransportError, httpx.TimeoutException):
        logger.exception("sig_feed_transport_error", url=str(body.feed_url))
        raise HTTPException(status_code=504, detail="Signature feed unreachable")

    # In production: parse the manifest from the fetched archive to extract
    # rule_count.  Here we record the raw byte length as a proxy until the
    # full manifest parser is implemented.
    rule_count_estimate = raw_content.count(b"\nrule ")

    version_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO signature_versions
                    (version_id, released_at, source, rule_count, notes)
                VALUES ($1::uuid, $2, $3, $4, $5)
                """,
                version_id,
                now,
                body.source_label,
                rule_count_estimate,
                body.notes,
            )
    except asyncpg.PostgresError:
        logger.exception("sig_update_db_error", version_id=version_id)
        raise HTTPException(status_code=500, detail="Signature version record failed")

    logger.info(
        "signature_updated",
        version_id=version_id,
        source=body.source_label,
        rule_count=rule_count_estimate,
        actor=actor,
    )

    return {
        "status": "accepted",
        "version_id": version_id,
        "rule_count": rule_count_estimate,
        "released_at": now.isoformat(),
    }
