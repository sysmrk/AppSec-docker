"""Make scan-only the default for newly scheduled image jobs.

Revision ID: 0007_pipeline_scan_by_default
Revises: 0006_redact_historical_secrets

Existing queued jobs are preserved as patch jobs for backward compatibility.
"""
from alembic import op

revision = "0007_pipeline_scan_by_default"
down_revision = "0006_redact_historical_secrets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE pipeline_jobs ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'patch'")
    op.execute("ALTER TABLE pipeline_jobs DROP CONSTRAINT IF EXISTS pipeline_jobs_mode_check")
    op.execute("ALTER TABLE pipeline_jobs ADD CONSTRAINT pipeline_jobs_mode_check CHECK (mode IN ('scan','patch'))")
    op.execute("ALTER TABLE pipeline_jobs ALTER COLUMN mode SET DEFAULT 'scan'")


def downgrade() -> None:
    op.execute("ALTER TABLE pipeline_jobs DROP CONSTRAINT IF EXISTS pipeline_jobs_mode_check")
    op.execute("ALTER TABLE pipeline_jobs DROP COLUMN IF EXISTS mode")
