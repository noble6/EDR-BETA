"""
database/pool.py
-----------------
asyncpg connection pool — created once at app startup, injected via Depends().

Architecture (fastapi-backend-skill):
  * Pool is created exactly once in the FastAPI lifespan event, never
    per-request.
  * `get_pool` is a FastAPI dependency that yields the pool; all routers
    use `Depends(get_pool)` and call `pool.acquire()` with an async context
    manager.
  * No credentials stored here — DATABASE_URL read exclusively from
    core.config.settings (populated from environment variables).
  * Never log full connection strings (fastapi-backend-skill: no logging
    of credentials even at debug level).
"""

from __future__ import annotations

from typing import AsyncGenerator, Optional

import asyncpg
import structlog
from fastapi import Request

logger = structlog.get_logger()

# Module-level pool reference — set during lifespan startup.
_pool: Optional[asyncpg.Pool] = None


async def create_pool(dsn: str) -> asyncpg.Pool:
    """
    Create and return an asyncpg connection pool.

    Called from the FastAPI lifespan handler in main.py — never inline
    in a request handler.

    Args:
        dsn: PostgreSQL connection string (from settings.DATABASE_URL).
             Must NOT be logged.
    """
    global _pool
    _pool = await asyncpg.create_pool(
        dsn=dsn,
        min_size=2,
        max_size=20,
        # Connections unused for 60s are recycled
        max_inactive_connection_lifetime=60,
        # Command timeout prevents runaway queries from blocking workers
        command_timeout=30,
    )
    logger.info("asyncpg_pool_created", min_size=2, max_size=20)
    return _pool


async def close_pool() -> None:
    """Gracefully close the connection pool on app shutdown."""
    global _pool
    if _pool is not None:
        await _pool.close()
        logger.info("asyncpg_pool_closed")
        _pool = None


async def get_pool(request: Request) -> AsyncGenerator[asyncpg.Pool, None]:
    """
    FastAPI dependency that yields the shared asyncpg pool.

    Usage in routers:
        pool: asyncpg.Pool = Depends(get_pool)
        async with pool.acquire() as conn:
            ...
    """
    pool: asyncpg.Pool = request.app.state.db_pool
    yield pool
