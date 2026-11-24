"""Repository credentials and publication audit evidence."""
from alembic import op
revision = "0017_repo_report_audit"
down_revision = "0016_scan_publication_evidence"
branch_labels = None
depends_on = None

def upgrade():
    op.execute("""CREATE TABLE IF NOT EXISTS repository_job_credentials (
        job_id UUID PRIMARY KEY REFERENCES security_jobs(id) ON DELETE CASCADE,
        ciphertext TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '1 hour'
    )""")
    op.execute("ALTER TABLE manual_workflows ADD COLUMN IF NOT EXISTS risk_reason TEXT")

def downgrade():
    op.execute("ALTER TABLE manual_workflows DROP COLUMN IF EXISTS risk_reason")
    op.execute("DROP TABLE IF EXISTS repository_job_credentials")
