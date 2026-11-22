"""Enable persisted, concurrency-safe manual workflows.

Revision ID: 0009_manual_workflows
Revises: 0008_service_heartbeats
"""
from alembic import op

revision = "0009_manual_workflows"
down_revision = "0008_service_heartbeats"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE pipeline_jobs DROP CONSTRAINT IF EXISTS pipeline_jobs_mode_check")
    op.execute("""
        ALTER TABLE pipeline_jobs ADD CONSTRAINT pipeline_jobs_mode_check
        CHECK (mode IN ('scan', 'patch', 'continue_patch'))
    """)
    op.execute("""
        CREATE TABLE manual_workflows (
            id UUID PRIMARY KEY,
            requested_image TEXT NOT NULL,
            project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
            created_by UUID NOT NULL REFERENCES users(id),
            scan_job_id UUID NOT NULL UNIQUE REFERENCES pipeline_jobs(id),
            patch_job_id UUID UNIQUE REFERENCES pipeline_jobs(id),
            decision TEXT CHECK (decision IN ('finish','approve_patch')),
            approved_by UUID REFERENCES users(id),
            approved_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT manual_workflows_decision_consistency CHECK (
              (decision = 'approve_patch' AND patch_job_id IS NOT NULL AND approved_by IS NOT NULL)
              OR (decision = 'finish' AND patch_job_id IS NULL AND approved_by IS NOT NULL)
              OR (decision IS NULL AND patch_job_id IS NULL)
            )
        )
    """)
    op.execute("CREATE INDEX idx_manual_workflows_creator_created ON manual_workflows(created_by, created_at DESC)")
    op.execute("CREATE INDEX idx_manual_workflows_project_created ON manual_workflows(project_id, created_at DESC)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS manual_workflows")
    op.execute("ALTER TABLE pipeline_jobs DROP CONSTRAINT IF EXISTS pipeline_jobs_mode_check")
    op.execute("""
        ALTER TABLE pipeline_jobs ADD CONSTRAINT pipeline_jobs_mode_check
        CHECK (mode IN ('scan', 'patch'))
    """)
