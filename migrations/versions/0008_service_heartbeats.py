"""Record worker and scheduler heartbeat timestamps for the Control Center.

Revision ID: 0008_service_heartbeats
Revises: 0007_pipeline_scan_by_default
"""
from alembic import op

revision = "0008_service_heartbeats"
down_revision = "0007_pipeline_scan_by_default"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS service_heartbeats (
            service TEXT NOT NULL,
            instance TEXT NOT NULL,
            last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (service, instance)
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS service_heartbeats")
