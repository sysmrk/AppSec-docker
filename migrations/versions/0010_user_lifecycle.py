"""Enterprise user lifecycle, lockouts and API-key rotation audit.

Revision ID: 0010_user_lifecycle
Revises: 0009_manual_workflows
"""
from alembic import op

revision = "0010_user_lifecycle"
down_revision = "0009_manual_workflows"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_count INTEGER NOT NULL DEFAULT 0")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS api_key_rotated_at TIMESTAMPTZ")

def downgrade() -> None:
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS api_key_rotated_at")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS password_changed_at")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS locked_until")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS failed_login_count")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS must_change_password")
