CREATE TABLE IF NOT EXISTS images (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    normalized_name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pipeline_runs (
    id UUID PRIMARY KEY,
    source_image_id UUID NOT NULL REFERENCES images(id),
    requested_image TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id UUID PRIMARY KEY,
    pipeline_id UUID REFERENCES pipeline_runs(id),
    image_id UUID NOT NULL REFERENCES images(id),
    image_ref TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('original', 'patched', 'manual')),
    status TEXT NOT NULL,
    report_path TEXT,
    raw_report JSONB,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    unknown_count INTEGER NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    target TEXT,
    vulnerability_id TEXT NOT NULL,
    pkg_name TEXT,
    installed_version TEXT,
    fixed_version TEXT,
    severity TEXT,
    title TEXT,
    primary_url TEXT
);

CREATE TABLE IF NOT EXISTS patch_runs (
    id UUID PRIMARY KEY,
    pipeline_id UUID NOT NULL REFERENCES pipeline_runs(id),
    source_scan_id UUID NOT NULL REFERENCES scan_runs(id),
    source_image_ref TEXT NOT NULL,
    patched_image_ref TEXT NOT NULL,
    status TEXT NOT NULL,
    copa_report_path TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS pipeline_jobs (
    id UUID PRIMARY KEY,
    requested_image TEXT NOT NULL,
    status TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 100,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    pipeline_id UUID REFERENCES pipeline_runs(id),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS scan_diffs (
    id UUID PRIMARY KEY,
    pipeline_id UUID NOT NULL REFERENCES pipeline_runs(id),
    original_scan_id UUID NOT NULL REFERENCES scan_runs(id),
    patched_scan_id UUID NOT NULL REFERENCES scan_runs(id),
    fixed_count INTEGER NOT NULL DEFAULT 0,
    remaining_count INTEGER NOT NULL DEFAULT 0,
    introduced_count INTEGER NOT NULL DEFAULT 0,
    fixed_vulnerabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    remaining_vulnerabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    introduced_vulnerabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policy_results (
    id UUID PRIMARY KEY,
    pipeline_id UUID NOT NULL REFERENCES pipeline_runs(id),
    scan_id UUID NOT NULL REFERENCES scan_runs(id),
    status TEXT NOT NULL,
    rules JSONB NOT NULL,
    violations JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS artifacts (
    id UUID PRIMARY KEY,
    pipeline_id UUID REFERENCES pipeline_runs(id),
    scan_id UUID REFERENCES scan_runs(id),
    image_ref TEXT NOT NULL,
    kind TEXT NOT NULL,
    format TEXT NOT NULL,
    path TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scheduled_images (
    id UUID PRIMARY KEY,
    image_ref TEXT NOT NULL UNIQUE,
    enabled BOOLEAN NOT NULL DEFAULT true,
    interval_minutes INTEGER NOT NULL DEFAULT 1440,
    last_enqueued_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    api_key_hash TEXT NOT NULL,
    password_hash TEXT,
    disabled BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS session_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

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

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS security_jobs (
    id UUID PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('secrets')),
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_by UUID REFERENCES users(id),
    report_path TEXT,
    raw_report JSONB,
    finding_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    info_count INTEGER NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    error_message TEXT
);

ALTER TABLE IF EXISTS security_jobs
    ADD COLUMN IF NOT EXISTS priority INTEGER NOT NULL DEFAULT 100,
    ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS max_attempts INTEGER NOT NULL DEFAULT 3,
    ADD COLUMN IF NOT EXISTS profile TEXT NOT NULL DEFAULT 'standard',
    ADD COLUMN IF NOT EXISTS last_error TEXT;

CREATE TABLE IF NOT EXISTS security_findings (
    id UUID PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES security_jobs(id) ON DELETE CASCADE,
    rule_id TEXT,
    severity TEXT,
    title TEXT,
    description TEXT,
    location TEXT,
    evidence TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS accepted_risks (
    id UUID PRIMARY KEY,
    finding_id UUID REFERENCES security_findings(id) ON DELETE CASCADE,
    scan_vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    owner TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    accepted_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS generated_reports (
    id UUID PRIMARY KEY,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    format TEXT NOT NULL,
    path TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_pipeline ON scan_runs(pipeline_id);
CREATE INDEX IF NOT EXISTS idx_scan_runs_image_phase ON scan_runs(image_id, phase);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_patch_runs_pipeline ON patch_runs(pipeline_id);
CREATE INDEX IF NOT EXISTS idx_pipeline_jobs_status_priority ON pipeline_jobs(status, priority, created_at);
CREATE INDEX IF NOT EXISTS idx_scan_diffs_pipeline ON scan_diffs(pipeline_id);
CREATE INDEX IF NOT EXISTS idx_policy_results_pipeline ON policy_results(pipeline_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_pipeline ON artifacts(pipeline_id);
CREATE INDEX IF NOT EXISTS idx_scheduled_images_enabled ON scheduled_images(enabled, last_enqueued_at);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_session_tokens_user ON session_tokens(user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_session_tokens_hash ON session_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id);
CREATE INDEX IF NOT EXISTS idx_projects_team ON projects(team_id);
CREATE INDEX IF NOT EXISTS idx_policies_project_active ON policies(project_id, active);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_security_jobs_kind_status ON security_jobs(kind, status, started_at);
CREATE INDEX IF NOT EXISTS idx_security_findings_job ON security_findings(job_id);
CREATE INDEX IF NOT EXISTS idx_accepted_risks_finding ON accepted_risks(finding_id);
CREATE INDEX IF NOT EXISTS idx_generated_reports_resource ON generated_reports(resource_type, resource_id);
