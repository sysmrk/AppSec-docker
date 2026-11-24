"""Persistent tool update state and execution evidence."""
from alembic import op
revision = "0018_tool_updates"
down_revision = "0017_repo_report_audit"
branch_labels = None
depends_on = None
def upgrade():
    op.execute("""CREATE TABLE IF NOT EXISTS tool_updates (
        tool TEXT PRIMARY KEY CHECK (tool IN ('copa','trivy','gitleaks')),
        current_version TEXT, latest_version TEXT, active_version TEXT,
        requested_version TEXT, status TEXT NOT NULL DEFAULT 'unchecked',
        checked_at TIMESTAMPTZ, requested_at TIMESTAMPTZ, applied_at TIMESTAMPTZ,
        last_error TEXT
    )""")
    op.execute("INSERT INTO tool_updates(tool) VALUES ('copa'),('trivy'),('gitleaks') ON CONFLICT DO NOTHING")
    op.execute("ALTER TABLE patch_runs ADD COLUMN IF NOT EXISTS execution_evidence JSONB DEFAULT '{}'::jsonb")
def downgrade():
    op.execute("ALTER TABLE patch_runs DROP COLUMN IF EXISTS execution_evidence")
    op.execute("DROP TABLE IF EXISTS tool_updates")
