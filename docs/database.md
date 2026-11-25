# Database and migrations — v2

PostgreSQL is the authoritative state store. Alembic migrations are applied before API/worker startup; the migration runner is built from the current checkout. Latest schema revision: 0018_tool_updates.

| Revision | Purpose |
| --- | --- |
| 0001–0005 | Baseline, enterprise scope, sessions/report access, secret-only scans, indexes |
| 0006 | Redact historical secret data in DB only |
| 0007–0009 | Scan-default jobs, heartbeats, manual approval workflow |
| 0010–0013 | User lifecycle, separate publication, inventory/registry, MFA |
| 0014 | Approved ordered image pull sources |
| 0015 | History purge / asynchronous local image removal |
| 0016 | Verified scan/publication evidence |
| 0017 | Encrypted expiring repository job credentials and publication risk reason |
| 0018 | Tool release/update state and patch execution evidence |

Core tables: images, pipeline_runs, pipeline_jobs, scan_runs, vulnerabilities, patch_runs, scan_diffs, policy_results, artifacts, generated_reports, manual_workflows, security_jobs, security_findings, repository_job_credentials, image_pull_sources, registry_connections, tool_updates, users, teams, team_members, projects, service_heartbeats and audit_logs.

Workflow approval locks serialize decisions. A successful execution is not a security recommendation. The initial scan stores findings without a policy decision; post-patch recommendations and explicit CI gate results are persisted separately by execution path. Publication records prepared/publishing/published/uncertain state, destination and digest.

Sessions/API keys and recovery codes are hashed, passwords salted PBKDF2, MFA secrets and transient repository credentials encrypted. Preserve APPSEC_MFA_ENCRYPTION_KEY separately; the derived repository credential key depends on it. Expired/consumed credentials are removed, not stored as findings. Backups can retain historical values.

Check revision without mutating data:

```bash
docker compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT version_num FROM alembic_version;"'
```

Back up PostgreSQL, object storage, report volume and encryption key together; preserve tool-updates volume and Docker local prepared images if needed. Restore into staging first. Metabase application database is separate; analytics access is not project-scoped.
