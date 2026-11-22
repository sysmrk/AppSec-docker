"""Remove Gitleaks secrets previously persisted in database tables.

Revision ID: 0006_redact_historical_secrets
Revises: 0005_perf_indexes

Note: filesystem/S3 artifacts and backups must be purged separately.
"""
from alembic import op

revision = "0006_redact_historical_secrets"
down_revision = "0005_perf_indexes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("UPDATE security_jobs SET raw_report = NULL WHERE kind = 'secrets'")
    op.execute("""
        UPDATE security_findings
        SET evidence = CASE WHEN evidence IS NULL THEN NULL ELSE '[REDACTED]' END,
            metadata = COALESCE(metadata, '{}'::jsonb) - 'secret'
        WHERE evidence IS NOT NULL OR metadata ? 'secret'
    """)


def downgrade() -> None:
    # This is an irreversible security cleanup. Never restore leaked secrets.
    pass
