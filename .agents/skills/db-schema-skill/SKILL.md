\---

name: db-schema-skill

description: Use when designing or modifying database/schema.sql — covers table design, indexing, and migration conventions for the antivirus backend's Postgres database.

\---



\# Database Schema Conventions



\## Purpose

Guide schema design for scan events, detections, quarantine records, and signature versioning in Postgres.



\## Core Tables (scaffolding only)

\- scan\_events — scan\_id, host\_id, start\_time, end\_time, files\_scanned, status

\- detections — detection\_id, scan\_id (FK), file\_path, signature\_id, severity, detected\_at

\- quarantine\_records — quarantine\_id, detection\_id (FK), quarantine\_path, hash, restored\_bool

\- signature\_versions — version\_id, released\_at, source, rule\_count

\- daemon\_health\_checks — host\_id, last\_heartbeat, cpu\_usage, memory\_usage



\## Conventions

\- Every table has a UUID primary key, not sequential integers, to avoid enumeration risk.

\- Time-series tables (scan\_events, detections) should be indexed on their timestamp column for dashboard query performance.

\- Use foreign key constraints with ON DELETE RESTRICT for detections/quarantine\_records to preserve audit trail integrity.

\- All migrations go through a versioned migration tool (e.g., Alembic), never manual ALTER statements in production.



\## Pitfalls

\- Avoid storing raw file content in the database — reference the quarantine filesystem path instead.

\- Don't index every column; over-indexing slows down high-volume scan\_event inserts.

