"""dashboard performance indexes

Revision ID: 0005_perf_indexes
Revises: 0004_secret_scans_only
Create Date: 2026-06-18
"""

from alembic import op


revision = "0005_perf_indexes"
down_revision = "0004_secret_scans_only"
branch_labels = None
depends_on = None


INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_scan_runs_phase_status_started ON scan_runs(phase, status, started_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_scan_runs_pipeline_phase_started ON scan_runs(pipeline_id, phase, started_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity_pkg ON vulnerabilities(severity, pkg_name)",
    "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_pkg_severity ON vulnerabilities(pkg_name, severity)",
    "CREATE INDEX IF NOT EXISTS idx_patch_runs_pipeline_started ON patch_runs(pipeline_id, started_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_scan_diffs_created ON scan_diffs(created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_policy_results_status_created ON policy_results(status, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_generated_reports_resource_created ON generated_reports(resource_type, resource_id, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_pipeline_runs_status_started ON pipeline_runs(status, started_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_pipeline_runs_requested_started ON pipeline_runs(requested_image, started_at DESC)",
]


def upgrade() -> None:
    for statement in INDEXES:
        op.execute(statement)


def downgrade() -> None:
    for name in reversed(
        [
            "idx_scan_runs_phase_status_started",
            "idx_scan_runs_pipeline_phase_started",
            "idx_vulnerabilities_severity_pkg",
            "idx_vulnerabilities_pkg_severity",
            "idx_patch_runs_pipeline_started",
            "idx_scan_diffs_created",
            "idx_policy_results_status_created",
            "idx_generated_reports_resource_created",
            "idx_pipeline_runs_status_started",
            "idx_pipeline_runs_requested_started",
        ]
    ):
        op.execute(f"DROP INDEX IF EXISTS {name}")
