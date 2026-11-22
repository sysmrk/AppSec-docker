"""Separate image preparation/rescanning from final registry publication.

Revision ID: 0011_manual_publication
Revises: 0010_user_lifecycle
"""
from alembic import op

revision = "0011_manual_publication"
down_revision = "0010_user_lifecycle"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.execute("ALTER TABLE patch_runs ADD COLUMN IF NOT EXISTS local_image_ref TEXT")
    op.execute("ALTER TABLE patch_runs ADD COLUMN IF NOT EXISTS publication_status TEXT NOT NULL DEFAULT 'unknown'")
    op.execute("ALTER TABLE patch_runs ADD COLUMN IF NOT EXISTS published_at TIMESTAMPTZ")
    op.execute("ALTER TABLE manual_workflows ADD COLUMN IF NOT EXISTS publish_job_id UUID REFERENCES pipeline_jobs(id)")
    op.execute("ALTER TABLE manual_workflows ADD COLUMN IF NOT EXISTS publish_decision TEXT")
    op.execute("ALTER TABLE manual_workflows ADD COLUMN IF NOT EXISTS published_by UUID REFERENCES users(id)")
    op.execute("ALTER TABLE manual_workflows ADD COLUMN IF NOT EXISTS publish_approved_at TIMESTAMPTZ")
    op.execute("ALTER TABLE manual_workflows DROP CONSTRAINT IF EXISTS manual_workflows_publish_decision_check")
    op.execute("""ALTER TABLE manual_workflows
        ADD CONSTRAINT manual_workflows_publish_decision_check
        CHECK (publish_decision IN ('approve_publish','skip_publish'))""")
    op.execute("ALTER TABLE pipeline_jobs DROP CONSTRAINT IF EXISTS pipeline_jobs_mode_check")
    op.execute("""ALTER TABLE pipeline_jobs ADD CONSTRAINT pipeline_jobs_mode_check
        CHECK (mode IN ('scan','patch','continue_patch','publish_patch'))""")

def downgrade() -> None:
    op.execute("ALTER TABLE pipeline_jobs DROP CONSTRAINT IF EXISTS pipeline_jobs_mode_check")
    op.execute("""ALTER TABLE pipeline_jobs ADD CONSTRAINT pipeline_jobs_mode_check
        CHECK (mode IN ('scan','patch','continue_patch'))""")
    op.execute("ALTER TABLE manual_workflows DROP COLUMN IF EXISTS publish_approved_at")
    op.execute("ALTER TABLE manual_workflows DROP COLUMN IF EXISTS published_by")
    op.execute("ALTER TABLE manual_workflows DROP COLUMN IF EXISTS publish_decision")
    op.execute("ALTER TABLE manual_workflows DROP COLUMN IF EXISTS publish_job_id")
    op.execute("ALTER TABLE patch_runs DROP COLUMN IF EXISTS published_at")
    op.execute("ALTER TABLE patch_runs DROP COLUMN IF EXISTS publication_status")
    op.execute("ALTER TABLE patch_runs DROP COLUMN IF EXISTS local_image_ref")
