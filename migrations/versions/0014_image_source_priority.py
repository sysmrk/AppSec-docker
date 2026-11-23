"""Priority-ordered registry mirrors for image acquisition.

Revision ID: 0014_image_source_priority
Revises: 0013_account_mfa
"""
from alembic import op

revision = "0014_image_source_priority"
down_revision = "0013_account_mfa"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS image_pull_sources (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            host TEXT NOT NULL,
            priority INTEGER NOT NULL CHECK (priority BETWEEN 1 AND 10000),
            enabled BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_image_pull_sources_order ON image_pull_sources(enabled, priority, created_at)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS image_pull_sources")
