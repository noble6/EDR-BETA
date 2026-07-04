\---

name: fastapi-backend-skill

description: Use when building or modifying av-backend endpoints in main.py — covers async patterns, auth, and secure API design for the antivirus management backend.

\---



\# FastAPI Backend Conventions for av-backend



\## Purpose

Guide the FastAPI service that receives scan events from av-daemon and serves the management dashboard.



\## Core Conventions

\- All database access uses asyncpg with a connection pool created once at app startup (lifespan event), never per-request.

\- Every route handler is async; no synchronous blocking calls (use httpx.AsyncClient for outbound calls, never requests).

\- Authentication is enforced via a FastAPI dependency (e.g., `Depends(verify\_token)`) applied at the router level, not duplicated per-endpoint.

\- Input validation happens exclusively through Pydantic models — never trust raw request bodies.



\## Security Requirements

\- Rate-limit signature-update and scan-trigger endpoints to prevent abuse \[web:8].

\- Never log full backend.conf credentials or tokens, even at debug level.

\- Return generic error messages to clients; log detailed errors server-side only.

\- Enforce HTTPS/mTLS between av-daemon and backend since backend.conf transmits an API endpoint and DB creds.



\## Suggested Module Structure

\- main.py — app instance, router registration, lifespan events

\- routers/scans.py — scan trigger + status endpoints

\- routers/quarantine.py — quarantine listing/release endpoints

\- routers/signatures.py — signature update endpoints

\- auth/ — token verification middleware

\- database/ — asyncpg pool + query functions

