"""Permit the signed native APT upgrade candidate strategy."""
from alembic import op
revision="0021_native_upgrade"
down_revision="0020_optimization"
branch_labels=None
depends_on=None


def upgrade():
    op.execute("ALTER TABLE optimization_runs DROP CONSTRAINT optimization_runs_operation_check")
    op.execute("ALTER TABLE optimization_runs ADD CONSTRAINT optimization_runs_operation_check CHECK(operation IN ('debloat','availability','inventory','upgrade'))")


def downgrade():
    # Do not silently remove upgrade audit history on downgrade.
    op.execute("ALTER TABLE optimization_runs DROP CONSTRAINT optimization_runs_operation_check")
    op.execute("ALTER TABLE optimization_runs ADD CONSTRAINT optimization_runs_operation_check CHECK(operation IN ('debloat','availability','inventory'))")
