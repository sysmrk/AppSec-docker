"""enterprise foundation

Revision ID: 0002_enterprise_foundation
Revises: 0001_baseline_schema
Create Date: 2026-06-18
"""

from alembic import op


revision = "0002_enterprise_foundation"
down_revision = "0001_baseline_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS teams (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );

        CREATE TABLE IF NOT EXISTS team_members (
            team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            role TEXT NOT NULL CHECK (role IN ('owner', 'maintainer', 'member', 'viewer')),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (team_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS projects (
            id UUID PRIMARY KEY,
            team_id UUID REFERENCES teams(id) ON DELETE SET NULL,
            name TEXT NOT NULL,
            slug TEXT NOT NULL UNIQUE,
            description TEXT,
            repo_url TEXT,
            registry_namespace TEXT,
            active BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );

        CREATE TABLE IF NOT EXISTS policies (
            id UUID PRIMARY KEY,
            project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            active BOOLEAN NOT NULL DEFAULT true,
            rules JSONB NOT NULL,
            created_by UUID REFERENCES users(id),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );

        ALTER TABLE IF EXISTS pipeline_runs
            ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id);

        ALTER TABLE IF EXISTS pipeline_jobs
            ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id);

        ALTER TABLE IF EXISTS security_jobs
            ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id);

        CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id);
        CREATE INDEX IF NOT EXISTS idx_projects_team ON projects(team_id);
        CREATE INDEX IF NOT EXISTS idx_policies_project_active ON policies(project_id, active);
        """
    )


def downgrade() -> None:
    pass
