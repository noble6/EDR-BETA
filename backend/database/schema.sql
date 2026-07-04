-- database/schema.sql
--
-- EDR-BETA antivirus management database schema (PostgreSQL 15+)
--
-- Design conventions (db-schema-skill):
--   * UUID primary keys everywhere — avoids enumeration risk vs sequential ints
--   * Time-series tables (scan_events, detections) indexed on their timestamp
--     column for dashboard query performance
--   * FK constraints use ON DELETE RESTRICT on detections/quarantine_records
--     to preserve audit trail integrity (no cascade deletes)
--   * All migrations via Alembic — never manual ALTER in production
--   * Raw file content is NEVER stored; only filesystem/quarantine paths
--   * Indexes are selective — not every column to protect high-volume insert
--     throughput on scan_events
--
-- Extensions
-- ----------
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- provides gen_random_uuid()

-- ============================================================================
-- TABLE: signature_versions
-- Tracks each released signature set so the dashboard can display currency.
-- ============================================================================
CREATE TABLE IF NOT EXISTS signature_versions (
    -- UUID PK (db-schema-skill: no sequential int to prevent enumeration)
    version_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    released_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source          VARCHAR(128) NOT NULL,   -- e.g. "edr-beta-internal", "clamav-official"
    rule_count      INTEGER NOT NULL CHECK (rule_count >= 0),
    manifest_path   TEXT,                    -- path to manifest.json on the backend host
    notes           TEXT
);

-- Only one index — released_at drives dashboard "latest signature" query
CREATE INDEX IF NOT EXISTS idx_sigver_released
    ON signature_versions (released_at DESC);

-- ============================================================================
-- TABLE: daemon_health_checks
-- Heartbeat records from each monitored endpoint's av-daemon instance.
-- ============================================================================
CREATE TABLE IF NOT EXISTS daemon_health_checks (
    check_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         VARCHAR(128) NOT NULL,
    last_heartbeat  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    daemon_version  VARCHAR(32),
    cpu_usage       NUMERIC(5, 2),    -- percentage 0.00–100.00
    memory_usage    BIGINT,           -- bytes
    sig_version_id  UUID REFERENCES signature_versions (version_id) ON DELETE SET NULL
);

-- Index on host_id so per-host health dashboard queries stay fast
CREATE INDEX IF NOT EXISTS idx_health_host
    ON daemon_health_checks (host_id, last_heartbeat DESC);

-- ============================================================================
-- TABLE: scan_events
-- One row per scan cycle initiated by the daemon.
-- ============================================================================
CREATE TABLE IF NOT EXISTS scan_events (
    scan_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         VARCHAR(128) NOT NULL,
    start_time      TIMESTAMPTZ NOT NULL,
    end_time        TIMESTAMPTZ,
    files_scanned   INTEGER NOT NULL DEFAULT 0 CHECK (files_scanned >= 0),
    status          VARCHAR(16) NOT NULL DEFAULT 'running'
                        CHECK (status IN ('running', 'completed', 'failed', 'aborted')),
    sig_version_id  UUID REFERENCES signature_versions (version_id) ON DELETE SET NULL
);

-- Time-series index: dashboard queries filter on start_time (db-schema-skill)
CREATE INDEX IF NOT EXISTS idx_scan_events_time
    ON scan_events (start_time DESC);

-- Per-host scans lookup (e.g., "show last 20 scans for host X")
CREATE INDEX IF NOT EXISTS idx_scan_events_host
    ON scan_events (host_id, start_time DESC);

-- ============================================================================
-- TABLE: detections
-- One row per file that matched a YARA/ClamAV signature during a scan.
-- ============================================================================
CREATE TABLE IF NOT EXISTS detections (
    detection_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- FK to the scan that produced this detection
    -- ON DELETE RESTRICT: preserve audit trail even if scan record is purged
    scan_id         UUID NOT NULL
                        REFERENCES scan_events (scan_id) ON DELETE RESTRICT,

    -- File identity
    file_path       TEXT NOT NULL,           -- original path on the endpoint
    sha256          CHAR(64) NOT NULL,       -- hex SHA-256 of the file at detection time
    file_size       BIGINT,

    -- Signature match info
    signature_id    VARCHAR(128) NOT NULL,   -- YARA rule identifier
    severity        VARCHAR(16) NOT NULL DEFAULT 'medium'
                        CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    description     TEXT,

    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Timestamp index for time-range dashboard queries (db-schema-skill)
CREATE INDEX IF NOT EXISTS idx_detections_time
    ON detections (detected_at DESC);

-- SHA-256 lookup for deduplication / reputation cross-reference
CREATE INDEX IF NOT EXISTS idx_detections_sha256
    ON detections (sha256);

-- Scan join index
CREATE INDEX IF NOT EXISTS idx_detections_scan
    ON detections (scan_id);

-- ============================================================================
-- TABLE: quarantine_records
-- Tracks every file moved to the quarantine directory.
-- Raw file content is NEVER stored here — only the quarantine filesystem path.
-- ============================================================================
CREATE TABLE IF NOT EXISTS quarantine_records (
    quarantine_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- FK: ON DELETE RESTRICT — quarantine record must outlive detection (audit)
    detection_id    UUID NOT NULL
                        REFERENCES detections (detection_id) ON DELETE RESTRICT,

    -- Quarantine storage
    quarantine_path TEXT NOT NULL,  -- path inside /opt/antivirus/quarantine/
    sha256          CHAR(64) NOT NULL,

    -- State
    restored        BOOLEAN NOT NULL DEFAULT FALSE,
    restored_at     TIMESTAMPTZ,
    restored_by     VARCHAR(128),   -- acting user identity (quarantine-handling-skill)

    deleted         BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at      TIMESTAMPTZ,
    deleted_by      VARCHAR(128),   -- acting user identity (quarantine-handling-skill)

    quarantined_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for dashboard "quarantine inbox" view
CREATE INDEX IF NOT EXISTS idx_quarantine_time
    ON quarantine_records (quarantined_at DESC);

-- Filter: show only active (not restored/deleted) quarantine items
CREATE INDEX IF NOT EXISTS idx_quarantine_active
    ON quarantine_records (restored, deleted, quarantined_at DESC);

-- ============================================================================
-- TABLE: av_scan_routers_audit
-- Audit log for all scan/quarantine/signature operations triggered via the
-- backend API.  Append-only — no UPDATE or DELETE allowed on this table.
-- ============================================================================
CREATE TABLE IF NOT EXISTS av_audit_log (
    audit_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_time      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor           VARCHAR(128) NOT NULL,   -- user/service account performing action
    action          VARCHAR(64)  NOT NULL,   -- e.g. "quarantine_restore", "sig_update"
    target_id       UUID,                    -- quarantine_id / detection_id / sig version_id
    target_type     VARCHAR(64),             -- "quarantine_record" | "detection" | "signature_version"
    details         JSONB                    -- arbitrary action context
);

CREATE INDEX IF NOT EXISTS idx_audit_time
    ON av_audit_log (event_time DESC);

CREATE INDEX IF NOT EXISTS idx_audit_actor
    ON av_audit_log (actor, event_time DESC);
