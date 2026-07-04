"""
migrations/versions/0001_av_suite_tables.py
-------------------------------------------
Alembic migration: create AV suite tables.

Tables created (db-schema-skill):
  - signature_versions
  - daemon_health_checks
  - scan_events
  - detections
  - quarantine_records
  - av_audit_log

Conventions:
  * UUID primary keys (gen_random_uuid via pgcrypto extension)
  * Timestamp indexes on time-series tables
  * FK ON DELETE RESTRICT on detections/quarantine_records (audit integrity)
  * No raw file content stored
  * All migrations via Alembic — never manual ALTER in production (db-schema-skill)
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Alembic revision identifiers
revision = "0001_av_suite_tables"
down_revision = None        # Base migration — no parent
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Enable pgcrypto for gen_random_uuid()
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')

    # ------------------------------------------------------------------
    # signature_versions
    # ------------------------------------------------------------------
    op.create_table(
        "signature_versions",
        sa.Column("version_id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("released_at", sa.TIMESTAMP(timezone=True),
                  server_default=sa.text("NOW()"), nullable=False),
        sa.Column("source", sa.String(128), nullable=False),
        sa.Column("rule_count", sa.Integer(), nullable=False),
        sa.Column("manifest_path", sa.Text(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.CheckConstraint("rule_count >= 0", name="ck_sig_rule_count_non_negative"),
    )
    op.create_index(
        "idx_sigver_released",
        "signature_versions",
        [sa.text("released_at DESC")],
    )

    # ------------------------------------------------------------------
    # daemon_health_checks
    # ------------------------------------------------------------------
    op.create_table(
        "daemon_health_checks",
        sa.Column("check_id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("host_id", sa.String(128), nullable=False),
        sa.Column("last_heartbeat", sa.TIMESTAMP(timezone=True),
                  server_default=sa.text("NOW()"), nullable=False),
        sa.Column("daemon_version", sa.String(32), nullable=True),
        sa.Column("cpu_usage", sa.Numeric(5, 2), nullable=True),
        sa.Column("memory_usage", sa.BigInteger(), nullable=True),
        sa.Column("sig_version_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["sig_version_id"], ["signature_versions.version_id"],
            ondelete="SET NULL",
        ),
    )
    op.create_index(
        "idx_health_host",
        "daemon_health_checks",
        ["host_id", sa.text("last_heartbeat DESC")],
    )

    # ------------------------------------------------------------------
    # scan_events  (time-series — indexed on start_time)
    # ------------------------------------------------------------------
    op.create_table(
        "scan_events",
        sa.Column("scan_id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("host_id", sa.String(128), nullable=False),
        sa.Column("start_time", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("end_time", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("files_scanned", sa.Integer(), server_default="0", nullable=False),
        sa.Column("status", sa.String(16), server_default="running", nullable=False),
        sa.Column("sig_version_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.CheckConstraint("files_scanned >= 0", name="ck_scan_files_scanned_non_negative"),
        sa.CheckConstraint(
            "status IN ('running', 'completed', 'failed', 'aborted')",
            name="ck_scan_status_valid",
        ),
        sa.ForeignKeyConstraint(
            ["sig_version_id"], ["signature_versions.version_id"],
            ondelete="SET NULL",
        ),
    )
    # Time-series index (db-schema-skill: dashboard filter on start_time)
    op.create_index(
        "idx_scan_events_time",
        "scan_events",
        [sa.text("start_time DESC")],
    )
    op.create_index(
        "idx_scan_events_host",
        "scan_events",
        ["host_id", sa.text("start_time DESC")],
    )

    # ------------------------------------------------------------------
    # detections  (FK → scan_events ON DELETE RESTRICT)
    # ------------------------------------------------------------------
    op.create_table(
        "detections",
        sa.Column("detection_id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("sha256", sa.CHAR(64), nullable=False),
        sa.Column("file_size", sa.BigInteger(), nullable=True),
        sa.Column("signature_id", sa.String(128), nullable=False),
        sa.Column("severity", sa.String(16), server_default="medium", nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("detected_at", sa.TIMESTAMP(timezone=True),
                  server_default=sa.text("NOW()"), nullable=False),
        sa.CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_detection_severity_valid",
        ),
        # ON DELETE RESTRICT: preserve audit trail (db-schema-skill)
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scan_events.scan_id"],
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "idx_detections_time",
        "detections",
        [sa.text("detected_at DESC")],
    )
    op.create_index("idx_detections_sha256", "detections", ["sha256"])
    op.create_index("idx_detections_scan", "detections", ["scan_id"])

    # ------------------------------------------------------------------
    # quarantine_records  (FK → detections ON DELETE RESTRICT)
    # ------------------------------------------------------------------
    op.create_table(
        "quarantine_records",
        sa.Column("quarantine_id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("detection_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("quarantine_path", sa.Text(), nullable=False),
        sa.Column("sha256", sa.CHAR(64), nullable=False),
        sa.Column("restored", sa.Boolean(), server_default="FALSE", nullable=False),
        sa.Column("restored_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("restored_by", sa.String(128), nullable=True),
        sa.Column("deleted", sa.Boolean(), server_default="FALSE", nullable=False),
        sa.Column("deleted_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("deleted_by", sa.String(128), nullable=True),
        sa.Column("quarantined_at", sa.TIMESTAMP(timezone=True),
                  server_default=sa.text("NOW()"), nullable=False),
        # ON DELETE RESTRICT: quarantine record must outlive detection (audit)
        sa.ForeignKeyConstraint(
            ["detection_id"], ["detections.detection_id"],
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "idx_quarantine_time",
        "quarantine_records",
        [sa.text("quarantined_at DESC")],
    )
    op.create_index(
        "idx_quarantine_active",
        "quarantine_records",
        ["restored", "deleted", sa.text("quarantined_at DESC")],
    )

    # ------------------------------------------------------------------
    # av_audit_log  (append-only audit trail)
    # ------------------------------------------------------------------
    op.create_table(
        "av_audit_log",
        sa.Column("audit_id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("event_time", sa.TIMESTAMP(timezone=True),
                  server_default=sa.text("NOW()"), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("target_type", sa.String(64), nullable=True),
        sa.Column("details", postgresql.JSONB(), nullable=True),
    )
    op.create_index(
        "idx_audit_time",
        "av_audit_log",
        [sa.text("event_time DESC")],
    )
    op.create_index(
        "idx_audit_actor",
        "av_audit_log",
        ["actor", sa.text("event_time DESC")],
    )


def downgrade() -> None:
    # Drop in reverse dependency order
    op.drop_table("av_audit_log")
    op.drop_table("quarantine_records")
    op.drop_table("detections")
    op.drop_table("scan_events")
    op.drop_table("daemon_health_checks")
    op.drop_table("signature_versions")
