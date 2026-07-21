"""
routers/scans.py
----------------
FastAPI router: scan trigger + scan status endpoints.

Architecture decisions (fastapi-backend-skill):
  * All handlers are async — no synchronous blocking calls.
  * Database access via asyncpg pool injected through Depends().
  * Auth is enforced at the router level in main.py, not repeated here.
  * Input validated exclusively through Pydantic models.
  * Errors returned as generic messages to clients; detailed errors logged
    server-side only (fastapi-backend-skill: security requirement).
  * Rate limiting on scan-trigger endpoint via SlowAPI (applied in main.py).

No hardcoded secrets — config values come from core.config.settings.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from backend.core.config import settings
from backend.db.pool import get_pool

logger = structlog.get_logger()
router = APIRouter(prefix="/scans", tags=["scans"])


# ---------------------------------------------------------------------------
# Pydantic models — all input validation through Pydantic (fastapi-backend-skill)
# ---------------------------------------------------------------------------

class ScanTriggerRequest(BaseModel):
    host_id: str = Field(..., min_length=1, max_length=128)
    # Relative path on the monitored host; backend records it as metadata only.
    # The daemon decides actual scope from its own config.
    target_path: Optional[str] = Field(None, max_length=512)
    sig_version_id: Optional[str] = Field(
        None,
        description="UUID of the signature version to use; None = latest"
    )


class ScanTriggerResponse(BaseModel):
    scan_id: str
    host_id: str
    status: str
    triggered_at: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    host_id: str
    status: str
    start_time: Optional[str]
    end_time: Optional[str]
    files_scanned: int
    detection_count: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/trigger", response_model=ScanTriggerResponse, status_code=202)
async def trigger_scan(
    request: Request,
    body: ScanTriggerRequest,
    pool: asyncpg.Pool = Depends(get_pool),
) -> ScanTriggerResponse:
    """
    Trigger a new scan cycle for a specific host.

    Creates a scan_events row in state 'running'.  The daemon polls for
    pending scans on its next heartbeat cycle and consumes this record.

    Rate-limited: max 10 scan triggers per host per minute (SlowAPI applied
    at router registration in main.py — fastapi-backend-skill requirement).
    """
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO scan_events
                    (scan_id, host_id, start_time, files_scanned, status, sig_version_id)
                VALUES ($1, $2, $3, 0, 'running', $4::uuid)
                """,
                scan_id,
                body.host_id,
                now,
                body.sig_version_id,  # NULL is valid → daemon picks latest
            )

        logger.info(
            "scan_triggered",
            scan_id=scan_id,
            host_id=body.host_id,
            actor=getattr(request.state, "agent_id", "unknown"),
        )

        return ScanTriggerResponse(
            scan_id=scan_id,
            host_id=body.host_id,
            status="running",
            triggered_at=now.isoformat(),
        )

    except asyncpg.PostgresError:
        # Log full error server-side; return generic message to client
        logger.exception("scan_trigger_db_error", host_id=body.host_id)
        raise HTTPException(status_code=500, detail="Scan trigger failed")


@router.get("/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: str,
    pool: asyncpg.Pool = Depends(get_pool),
) -> ScanStatusResponse:
    """
    Retrieve status and summary metrics for a scan by its UUID.

    Joins scan_events with a COUNT on detections so the dashboard gets a
    single response without a second round-trip.
    """
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT
                    se.scan_id,
                    se.host_id,
                    se.status,
                    se.start_time,
                    se.end_time,
                    se.files_scanned,
                    COUNT(d.detection_id) AS detection_count
                FROM scan_events se
                LEFT JOIN detections d ON d.scan_id = se.scan_id
                WHERE se.scan_id = $1::uuid
                GROUP BY se.scan_id
                """,
                scan_id,
            )
    except asyncpg.PostgresError:
        logger.exception("scan_status_db_error", scan_id=scan_id)
        raise HTTPException(status_code=500, detail="Status lookup failed")

    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanStatusResponse(
        scan_id=str(row["scan_id"]),
        host_id=row["host_id"],
        status=row["status"],
        start_time=row["start_time"].isoformat() if row["start_time"] else None,
        end_time=row["end_time"].isoformat() if row["end_time"] else None,
        files_scanned=row["files_scanned"],
        detection_count=row["detection_count"],
    )


@router.patch("/{scan_id}/complete")
async def mark_scan_complete(
    scan_id: str,
    files_scanned: int,
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    """
    Called by av-daemon to close out a scan cycle.
    Only the daemon's API key can reach this endpoint (enforced at router level).
    """
    try:
        async with pool.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE scan_events
                SET status = 'completed',
                    end_time = NOW(),
                    files_scanned = $2
                WHERE scan_id = $1::uuid AND status = 'running'
                """,
                scan_id,
                files_scanned,
            )

        if result == "UPDATE 0":
            raise HTTPException(status_code=404, detail="Scan not found or already closed")

        logger.info("scan_completed", scan_id=scan_id, files_scanned=files_scanned)
        return {"status": "ok", "scan_id": scan_id}

    except asyncpg.PostgresError:
        logger.exception("scan_complete_db_error", scan_id=scan_id)
        raise HTTPException(status_code=500, detail="Scan update failed")
