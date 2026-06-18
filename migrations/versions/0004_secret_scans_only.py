"""limit code security jobs to secret scans

Revision ID: 0004_secret_scans_only
Revises: 0003_sessions_and_report_access
Create Date: 2026-06-18
"""

from alembic import op


revision = "0004_secret_scans_only"
down_revision = "0003_sessions_and_report_access"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DELETE FROM generated_reports gr
        USING security_jobs sj
        WHERE gr.resource_type = 'security_job'
          AND gr.resource_id = sj.id::text
          AND sj.kind <> 'secrets'
        """
    )
    op.execute("DELETE FROM security_jobs WHERE kind <> 'secrets'")
    op.execute("ALTER TABLE security_jobs DROP CONSTRAINT IF EXISTS security_jobs_kind_check")
    op.execute("ALTER TABLE security_jobs ADD CONSTRAINT security_jobs_kind_check CHECK (kind IN ('secrets'))")


def downgrade() -> None:
    op.execute("ALTER TABLE security_jobs DROP CONSTRAINT IF EXISTS security_jobs_kind_check")
    op.execute("ALTER TABLE security_jobs ADD CONSTRAINT security_jobs_kind_check CHECK (kind IN ('secrets'))")
