"""Store prepared image identity and published manifest digest."""
from alembic import op

revision = "0016_scan_publication_evidence"
down_revision = "0015_history_purge"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("ALTER TABLE patch_runs ADD COLUMN IF NOT EXISTS local_image_id TEXT")
    op.execute("ALTER TABLE patch_runs ADD COLUMN IF NOT EXISTS published_digest TEXT")


def downgrade():
    op.execute("ALTER TABLE patch_runs DROP COLUMN IF EXISTS published_digest")
    op.execute("ALTER TABLE patch_runs DROP COLUMN IF EXISTS local_image_id")
