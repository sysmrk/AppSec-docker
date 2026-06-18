"""sessions and report access

Revision ID: 0003_sessions_and_report_access
Revises: 0002_enterprise_foundation
Create Date: 2026-06-18
"""

from alembic import op


revision = "0003_sessions_and_report_access"
down_revision = "0002_enterprise_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT")
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS session_tokens (
            id UUID PRIMARY KEY,
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            expires_at TIMESTAMPTZ NOT NULL,
            revoked_at TIMESTAMPTZ
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_session_tokens_user ON session_tokens(user_id, expires_at)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_session_tokens_hash ON session_tokens(token_hash)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_session_tokens_hash")
    op.execute("DROP INDEX IF EXISTS idx_session_tokens_user")
    op.execute("DROP TABLE IF EXISTS session_tokens")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS password_hash")
