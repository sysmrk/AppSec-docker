"""Queue Docker tag cleanup following a destructive pipeline history purge.

Revision ID: 0015_history_purge
Revises: 0014_image_source_priority
"""
from alembic import op

revision = "0015_history_purge"
down_revision = "0014_image_source_priority"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS pending_image_removals(
            id UUID PRIMARY KEY,
            image_ref TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'queued',
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS pending_image_removals")
