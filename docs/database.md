# Database and migrations

PostgreSQL is the source of truth. Schema baseline: [db/schema.sql](../db/schema.sql), version upgrades: [Alembic migrations](../migrations/versions/), applied by `./appsec start`.

## Main relations

| Table | Meaning |
| --- | --- |
| `users`, `session_tokens`, `teams`, `team_members`, `projects` | Identity, session and authorization |
| `images`, `pipeline_runs`, `pipeline_jobs` | Image references, pipeline attempts and queue; `mode` is `scan`, `patch` or internal `continue_patch` |
| `manual_workflows` | Human-created workflow and persisted finish/patch decisions |
| `scan_runs`, `vulnerabilities` | Trivy scan metadata, counts and CVE/package findings |
| `patch_runs`, `scan_diffs` | Optional Copa patch status and original-vs-patched findings |
| `artifacts`, `generated_reports` | SBOM, JSON and HTML paths plus download IDs |
| `policy_results`, `policies` | Security policy rules and decisions |
| `security_jobs`, `security_findings` | Gitleaks jobs and redacted findings |
| `audit_logs`, `accepted_risks` | Security changes, approvals and expiring exceptions |
| `service_heartbeats` | Worker/Scheduler liveness for the admin System Health view |
| `scheduled_images` | Recurring scan registrations |

## Manual workflow lifecycle

`manual_workflows` stores `requested_image`, `project_id`, `created_by`, `scan_job_id`, optional `patch_job_id`, optional `decision` (`finish` or `approve_patch`), `approved_by`, `approved_at`, and timestamps. It has database constraints preventing patch jobs without corresponding approval metadata.

The initial job is always scan-only. A completed original scan and policy result must exist before an operator can finish or authorize a patch. The API locks the workflow row to serialize concurrent decisions. The approved continuation job uses `mode=continue_patch`, points to the **same** pipeline, and has `max_attempts=1`.

Job status and pipeline status are joined to derive the workflow view; no fake progress timers or fabricated findings are stored.

## Migration history / upgrade warnings

- **0006:** redacts historical Gitleaks secrets in PostgreSQL. Old report files, S3/MinIO objects and backups need manual cleanup and credential rotation.
- **0007:** defaults new image queue entries to `scan`; pre-existing queued work preserves patch behavior for backward compatibility.
- **0008:** adds heartbeat telemetry.
- **0009:** introduces manual workflows and authorized `continue_patch` job mode.

Back up before migrations and validate on a staging copy first. The initial schema includes the latest tables for legacy `init-db` compatibility; migrations use idempotent DDL where appropriate. Repeated `alembic upgrade head` must be safe.

## Access and retention

Reports require an AppSec login or API Key, with Project authorization. Unassigned guided runs are visible to creator/admin; Project runs to current Team members. Metabase uses its **separate** authentication and currently has global analytics access; for production use a least-privilege read-only DB role.

If your organization has retention/deletion requirements, evaluate PostgreSQL, Docker volumes, S3/MinIO, backup snapshots, and Metabase's own database separately. Deleting a report link does not revoke exposed credentials.
