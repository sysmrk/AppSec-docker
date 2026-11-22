"""Optional encrypted TOTP with single-use recovery code lifecycle.

Revision ID: 0013_account_mfa
Revises: 0012_image_inventory
"""
from alembic import op

revision = "0013_account_mfa"
down_revision = "0012_image_inventory"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT false")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret_enc TEXT")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_pending_enc TEXT")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_pending_at TIMESTAMPTZ")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_last_step BIGINT NOT NULL DEFAULT -1")
    op.execute("""
        CREATE TABLE IF NOT EXISTS mfa_recovery_codes(
            id UUID PRIMARY KEY,
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code_hash TEXT NOT NULL,
            used_at TIMESTAMPTZ,
            UNIQUE(user_id, code_hash)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_mfa_recovery_user ON mfa_recovery_codes(user_id) WHERE used_at IS NULL")

def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS mfa_recovery_codes")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS mfa_last_step")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS mfa_pending_at")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS mfa_pending_enc")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS mfa_secret_enc")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS mfa_enabled")
