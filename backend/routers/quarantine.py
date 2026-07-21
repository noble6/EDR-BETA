"""
routers/quarantine.py
----------------------
FastAPI router: quarantine listing, release (restore), and delete endpoints.

Security design (fastapi-backend-skill + quarantine-handling-skill):
  * Listing quarantined items is read-only — no risk.
  * Restore/delete require explicit admin action — never automatic.
  * Every restore/delete action is written to av_audit_log with the acting
    user's identity (quarantine-handling-skill audit requirement).
  * All DB access via asyncpg pool — no blocking I/O.
  * Input validated through Pydantic — never trust raw request bodies.
  * Errors: generic to client, detailed server-side.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional
import uuid

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from backend.db.pool import get_pool

logger = structlog.get_logger()
router = APIRouter(prefix="/quarantine", tags=["quarantine"])


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class QuarantineRecord(BaseModel):
    quarantine_id: str
    detection_id: str
    quarantine_path: str
    sha256: str
    restored: bool
    deleted: bool
    quarantined_at: str


class QuarantineListResponse(BaseModel):
    items: List[QuarantineRecord]
    total: int


class RestoreRequest(BaseModel):
    # Reason must be provided for audit trail
    reason: str = Field(..., min_length=5, max_length=512)


class DeleteRequest(BaseModel):
    reason: str = Field(..., min_length=5, max_length=512)
    # Explicit confirmation flag — defence against accidental API calls
    confirmed: bool = Field(
        ...,
        description="Must be true to proceed with permanent deletion"
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", response_model=QuarantineListResponse)
async def list_quarantine(
    host_id: Optional[str] = None,
    active_only: bool = True,
    limit: int = 50,
    offset: int = 0,
    pool: asyncpg.Pool = Depends(get_pool),
) -> QuarantineListResponse:
    """
    List quarantined files.  Defaults to active items only (not restored/deleted).
    Optionally filter by host_id via the detection → scan_events join.
    """
    try:
        async with pool.acquire() as conn:
            base_query = """
                SELECT
                    qr.quarantine_id,
                    qr.detection_id,
                    qr.quarantine_path,
                    qr.sha256,
                    qr.restored,
                    qr.deleted,
                    qr.quarantined_at
                FROM quarantine_records qr
                JOIN detections d ON d.detection_id = qr.detection_id
                JOIN scan_events se ON se.scan_id = d.scan_id
            """

            conditions = []
            params: list = []
            p = 1

            if active_only:
                conditions.append(f"qr.restored = FALSE AND qr.deleted = FALSE")

            if host_id:
                conditions.append(f"se.host_id = ${p}")
                params.append(host_id)
                p += 1

            if conditions:
                base_query += " WHERE " + " AND ".join(conditions)

            base_query += f" ORDER BY qr.quarantined_at DESC LIMIT ${p} OFFSET ${p+1}"
            params.extend([limit, offset])

            rows = await conn.fetch(base_query, *params)

            # Count query for pagination metadata
            count_query = base_query.split("ORDER BY")[0].replace(
                "SELECT\n                    qr.quarantine_id,\n                    qr.detection_id,\n                    qr.quarantine_path,\n                    qr.sha256,\n                    qr.restored,\n                    qr.deleted,\n                    qr.quarantined_at",
                "SELECT COUNT(*)"
            )
            total = await conn.fetchval(count_query, *params[:-2])

        return QuarantineListResponse(
            items=[
                QuarantineRecord(
                    quarantine_id=str(r["quarantine_id"]),
                    detection_id=str(r["detection_id"]),
                    quarantine_path=r["quarantine_path"],
                    sha256=r["sha256"],
                    restored=r["restored"],
                    deleted=r["deleted"],
                    quarantined_at=r["quarantined_at"].isoformat(),
                )
                for r in rows
            ],
            total=total or 0,
        )

    except asyncpg.PostgresError:
        logger.exception("quarantine_list_db_error")
        raise HTTPException(status_code=500, detail="Failed to retrieve quarantine list")


@router.post("/{quarantine_id}/restore")
async def restore_quarantined_file(
    quarantine_id: str,
    body: RestoreRequest,
    request: Request,
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    """
    Restore a quarantined file to its original location.

    Explicit admin action required — never automatic (quarantine-handling-skill).
    Acting user identity captured from request.state.agent_id (set by auth middleware).
    Action written to av_audit_log.
    """
    actor = getattr(request.state, "agent_id", "unknown")

    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    SELECT quarantine_id, restored, deleted
                    FROM quarantine_records
                    WHERE quarantine_id = $1::uuid
                    FOR UPDATE
                    """,
                    quarantine_id,
                )

                if row is None:
                    raise HTTPException(status_code=404, detail="Quarantine record not found")

                if row["restored"]:
                    raise HTTPException(status_code=409, detail="File already restored")

                if row["deleted"]:
                    raise HTTPException(status_code=409, detail="File has been permanently deleted")

                now = datetime.now(timezone.utc)

                await conn.execute(
                    """
                    UPDATE quarantine_records
                    SET restored = TRUE,
                        restored_at = $2,
                        restored_by = $3
                    WHERE quarantine_id = $1::uuid
                    """,
                    quarantine_id,
                    now,
                    actor,
                )

                # Audit log entry (quarantine-handling-skill)
                await conn.execute(
                    """
                    INSERT INTO av_audit_log
                        (audit_id, actor, action, target_id, target_type, details)
                    VALUES ($1, $2, 'quarantine_restore', $3::uuid, 'quarantine_record',
                            $4::jsonb)
                    """,
                    str(uuid.uuid4()),
                    actor,
                    quarantine_id,
                    f'{{"reason": "{body.reason}"}}',
                )

        logger.info(
            "quarantine_restored",
            quarantine_id=quarantine_id,
            actor=actor,
            reason=body.reason,
        )
        return {"status": "ok", "quarantine_id": quarantine_id, "action": "restored"}

    except HTTPException:
        raise
    except asyncpg.PostgresError:
        logger.exception("quarantine_restore_db_error", quarantine_id=quarantine_id)
        raise HTTPException(status_code=500, detail="Restore operation failed")


@router.delete("/{quarantine_id}")
async def delete_quarantined_file(
    quarantine_id: str,
    body: DeleteRequest,
    request: Request,
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    """
    Permanently delete a quarantined file record.

    Requires explicit 'confirmed: true' in request body and a reason string.
    Acting user identity captured and written to av_audit_log.
    (quarantine-handling-skill: deletion requires confirmation + audit with user identity)
    """
    if not body.confirmed:
        raise HTTPException(
            status_code=422,
            detail="confirmed must be true to perform permanent deletion"
        )

    actor = getattr(request.state, "agent_id", "unknown")

    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    SELECT quarantine_id, deleted
                    FROM quarantine_records
                    WHERE quarantine_id = $1::uuid
                    FOR UPDATE
                    """,
                    quarantine_id,
                )

                if row is None:
                    raise HTTPException(status_code=404, detail="Quarantine record not found")

                if row["deleted"]:
                    raise HTTPException(status_code=409, detail="Already deleted")

                now = datetime.now(timezone.utc)

                await conn.execute(
                    """
                    UPDATE quarantine_records
                    SET deleted = TRUE,
                        deleted_at = $2,
                        deleted_by = $3
                    WHERE quarantine_id = $1::uuid
                    """,
                    quarantine_id,
                    now,
                    actor,
                )

                # Audit log with acting user (quarantine-handling-skill)
                await conn.execute(
                    """
                    INSERT INTO av_audit_log
                        (audit_id, actor, action, target_id, target_type, details)
                    VALUES ($1, $2, 'quarantine_delete', $3::uuid, 'quarantine_record',
                            $4::jsonb)
                    """,
                    str(uuid.uuid4()),
                    actor,
                    quarantine_id,
                    f'{{"reason": "{body.reason}"}}',
                )

        logger.info(
            "quarantine_deleted",
            quarantine_id=quarantine_id,
            actor=actor,
            reason=body.reason,
        )
        return {"status": "ok", "quarantine_id": quarantine_id, "action": "deleted"}

    except HTTPException:
        raise
    except asyncpg.PostgresError:
        logger.exception("quarantine_delete_db_error", quarantine_id=quarantine_id)
        raise HTTPException(status_code=500, detail="Delete operation failed")
