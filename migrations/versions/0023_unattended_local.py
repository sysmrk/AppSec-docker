"""Persist explicit pre-start authorization; existing jobs remain guided."""
from alembic import op
revision="0023_unattended_local"
down_revision="0022_guided_execution"
branch_labels=None
depends_on=None


def upgrade():
    op.execute("ALTER TABLE manual_workflows ADD COLUMN unattended BOOLEAN NOT NULL DEFAULT false")


def downgrade():
    op.execute("ALTER TABLE manual_workflows DROP COLUMN unattended")
