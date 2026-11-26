"""Bounded per-job progress history; never store tool output verbatim."""
from alembic import op
revision = "0019_job_watch"
down_revision = "0018_tool_updates"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""CREATE TABLE job_watch_events (
        id BIGSERIAL PRIMARY KEY,
        image_job_id UUID REFERENCES pipeline_jobs(id) ON DELETE CASCADE,
        security_job_id UUID REFERENCES security_jobs(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        event TEXT NOT NULL,
        detail TEXT NOT NULL,
        CHECK ((image_job_id IS NULL) <> (security_job_id IS NULL))
    )""")
    op.execute("CREATE INDEX job_watch_image_idx ON job_watch_events(image_job_id,id)")
    op.execute("CREATE INDEX job_watch_security_idx ON job_watch_events(security_job_id,id)")


def downgrade():
    op.execute("DROP TABLE job_watch_events")
