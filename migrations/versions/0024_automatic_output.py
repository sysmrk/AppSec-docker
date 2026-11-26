"""Persist the explicit optional registry destination for unattended Copa output."""
from alembic import op
revision="0024_automatic_output"
down_revision="0023_unattended_local"
branch_labels=None
depends_on=None


def upgrade():
    op.execute("ALTER TABLE manual_workflows ADD COLUMN auto_destination TEXT")


def downgrade():
    op.execute("ALTER TABLE manual_workflows DROP COLUMN auto_destination")
