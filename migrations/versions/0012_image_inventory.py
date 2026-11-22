"""Registry connections and scanning inventory indexes.

Revision ID: 0012_image_inventory
Revises: 0011_manual_publication
"""
from alembic import op

revision = "0012_image_inventory"
down_revision = "0011_manual_publication"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS registry_connections (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            host TEXT NOT NULL UNIQUE,
            project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
            allow_push BOOLEAN NOT NULL DEFAULT false,
            created_by UUID REFERENCES users(id),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_scans_image_started ON scan_runs(image_id, started_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_image_started ON pipeline_runs(source_image_id, started_at DESC)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_pipeline_image_started")
    op.execute("DROP INDEX IF EXISTS idx_scans_image_started")
    op.execute("DROP TABLE IF EXISTS registry_connections")
