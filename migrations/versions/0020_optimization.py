"""Local-only optimization task queue and approved package source priority."""
from alembic import op
revision="0020_optimization"
down_revision="0019_job_watch"
branch_labels=None
depends_on=None


def upgrade():
    op.execute("""CREATE TABLE package_mirror_settings (
        id INTEGER PRIMARY KEY CHECK(id=1),
        mirrors JSONB NOT NULL DEFAULT '[]'::jsonb,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )""")
    op.execute("INSERT INTO package_mirror_settings(id) VALUES(1)")
    op.execute("""CREATE TABLE optimization_runs (
        id UUID PRIMARY KEY,
        workflow_id UUID NOT NULL REFERENCES manual_workflows(id) ON DELETE CASCADE,
        scan_id UUID NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
        created_by UUID REFERENCES users(id) ON DELETE SET NULL,
        approved_by UUID REFERENCES users(id) ON DELETE SET NULL,
        stage TEXT NOT NULL CHECK(stage IN ('original','residual')),
        operation TEXT NOT NULL CHECK(operation IN ('debloat','availability','inventory')),
        roots JSONB NOT NULL DEFAULT '[]'::jsonb,
        mirrors JSONB NOT NULL DEFAULT '[]'::jsonb,
        state TEXT NOT NULL CHECK(state IN ('queued','planning','awaiting_approval','build_queued','building','completed','failed','canceled')),
        plan JSONB, result JSONB, error_code TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )""")
    op.execute("""CREATE UNIQUE INDEX optimization_active_workflow
        ON optimization_runs(workflow_id) WHERE state IN ('queued','planning','awaiting_approval','build_queued','building')""")
    op.execute("CREATE INDEX optimization_queue ON optimization_runs(state,created_at)")
    op.execute("ALTER TABLE job_watch_events ADD COLUMN optimization_id UUID REFERENCES optimization_runs(id) ON DELETE CASCADE")
    # Replace the original anonymous check by name discovered through the schema.
    op.execute("ALTER TABLE job_watch_events DROP CONSTRAINT job_watch_events_check")
    op.execute("ALTER TABLE job_watch_events ADD CHECK (num_nonnulls(image_job_id,security_job_id,optimization_id)=1)")
    op.execute("CREATE INDEX job_watch_optimization_idx ON job_watch_events(optimization_id,id)")


def downgrade():
    op.execute("DELETE FROM job_watch_events WHERE optimization_id IS NOT NULL")
    op.execute("ALTER TABLE job_watch_events DROP COLUMN optimization_id")
    op.execute("ALTER TABLE job_watch_events ADD CHECK ((image_job_id IS NULL) <> (security_job_id IS NULL))")
    op.execute("DROP TABLE optimization_runs")
    op.execute("DROP TABLE package_mirror_settings")
