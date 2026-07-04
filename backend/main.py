from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import structlog
import time
import os

from core.config import settings
from core.schemas import APIResponse
from api.routes import router as api_router
from auth.dependencies import verify_agent_key, verify_dashboard_token

# ---------------------------------------------------------------------------
# Structured logger
# ---------------------------------------------------------------------------
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ]
)
logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Rate limiter (fastapi-backend-skill: rate-limit signature-update + scan-trigger)
# Key function uses remote IP; in prod behind a reverse-proxy use X-Forwarded-For.
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)

# ---------------------------------------------------------------------------
# Lifespan: create asyncpg pool once at startup, close on shutdown
# (fastapi-backend-skill: pool created once, never per-request)
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Startup ---
    from database.pool import create_pool

    # DSN comes from env var → settings — never logged
    dsn = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
    app.state.db_pool = await create_pool(dsn)
    logger.info("asyncpg_pool_ready")
    yield

    # --- Shutdown ---
    from database.pool import close_pool
    await close_pool()
    logger.info("asyncpg_pool_closed")

# ---------------------------------------------------------------------------
# App instance
# ---------------------------------------------------------------------------
app = FastAPI(
    title=settings.PROJECT_NAME,
    lifespan=lifespan,
)

# Attach SlowAPI to the app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---------------------------------------------------------------------------
# CORS
# Note: allow_origins=["*"] is acceptable for daemon↔backend (non-browser)
# traffic. Restrict to dashboard domain in production if the dashboard is
# served from a different origin.
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Request logging middleware
# ---------------------------------------------------------------------------
@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    logger.info(
        "http_request",
        method=request.method,
        url=str(request.url),
        status_code=response.status_code,
        duration=round(duration, 4),
        agent_id=getattr(request.state, "agent_id", "unknown"),
    )
    return response

# ---------------------------------------------------------------------------
# Exception handlers (fastapi-backend-skill: generic messages to client)
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("unhandled_server_exception", error=str(exc), path=str(request.url))
    return JSONResponse(
        status_code=500,
        content={"status": "error", "error": {"message": "Internal Server Error"}},
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    detail = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail)}
    return JSONResponse(
        status_code=exc.status_code,
        content={"status": "error", "error": detail},
    )

# ---------------------------------------------------------------------------
# Router registration
# ---------------------------------------------------------------------------

# ── Existing agent API (unchanged) ──────────────────────────────────────────
app.include_router(
    api_router,
    prefix=settings.API_V1_STR,
    dependencies=[Depends(verify_agent_key)],
)

# ── New AV management routers ────────────────────────────────────────────────
from routers.scans import router as scans_router
from routers.quarantine import router as quarantine_router
from routers.signatures import router as signatures_router

# /av/scans — daemon-facing; protected by agent API key auth
# Rate limit: 30 scan triggers per minute per IP (scan-trigger endpoint has
# its own tighter @limiter.limit decorator applied inside the router).
app.include_router(
    scans_router,
    prefix="/av",
    dependencies=[Depends(verify_agent_key)],
)

# /av/quarantine — admin-facing; also behind agent key for daemon reporting,
# but restore/delete actions additionally check acting user inside the handler.
app.include_router(
    quarantine_router,
    prefix="/av",
    dependencies=[Depends(verify_agent_key)],
)

# /av/signatures — rate-limited at the endpoint level via @limiter.limit;
# router-level auth uses agent key so daemon can pull latest version_id.
app.include_router(
    signatures_router,
    prefix="/av",
    dependencies=[Depends(verify_agent_key)],
)

# ── Dashboard routes (existing) ───────────────────────────────────────────────
from api.dashboard_routes import router as dashboard_router
app.include_router(dashboard_router, prefix="/api/dashboard")

# ---------------------------------------------------------------------------
# Static dashboard (existing)
# ---------------------------------------------------------------------------
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/dashboard", StaticFiles(directory=frontend_path, html=True), name="frontend")

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.get("/health")
async def health_check():
    return APIResponse(status="success", data={"version": "1.0.0"})
