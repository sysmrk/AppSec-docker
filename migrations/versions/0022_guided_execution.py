"""Preselected workflow route and cooperative stop request."""
from alembic import op
revision="0022_guided_execution"
down_revision="0021_native_upgrade"
branch_labels=None
depends_on=None


def upgrade():
    op.execute("ALTER TABLE manual_workflows ADD COLUMN execution_mode TEXT NOT NULL DEFAULT 'guided' CHECK(execution_mode IN ('guided','scan_only','auto_patch','auto_optimize'))")
    op.execute("ALTER TABLE manual_workflows ADD COLUMN optimization_roots JSONB NOT NULL DEFAULT '[]'::jsonb")
    op.execute("ALTER TABLE manual_workflows ADD COLUMN stop_requested_at TIMESTAMPTZ")
    op.execute("ALTER TABLE manual_workflows ADD COLUMN auto_step TEXT")
    op.execute("ALTER TABLE manual_workflows ADD COLUMN auto_error TEXT")


def downgrade():
    for name in ("auto_error","auto_step","stop_requested_at","optimization_roots","execution_mode"):
        op.execute("ALTER TABLE manual_workflows DROP COLUMN "+name)
