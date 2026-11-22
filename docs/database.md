# Database

The initial schema lives in [db/schema.sql](../db/schema.sql). Versioned upgrades use [Alembic migrations](../migrations/versions/) and are automatically applied by `./appsec start`.

## Main tables

| Table | Purpose |
| --- | --- |
| `images` | Unique image references |
| `pipeline_runs` | A scan-only or explicit patch-enabled execution |
| `scan_runs` | Individual Trivy scans, phase `original`, `patched`, or `manual` |
| `vulnerabilities` | Parsed per-scan CVE and package details |
| `patch_runs` | Optional Copa patch and registry push results |
| `pipeline_jobs` | Queue, priority, status, `mode` (`scan` or `patch`), Project and pipeline ID |
| `scan_diffs` | Fixed/remaining/introduced CVEs after optional patch |
| `policy_results` | Policy decision on the last relevant scan |
| `artifacts` | Stored SBOM, Trivy JSON and other files |
| `scheduled_images` | Images queued on a recurrence |
| `security_jobs`/`security_findings` | Secret scans and redacted findings |
| `projects`/`users`/`team_members` | Identity and Project authorization |
| `generated_reports` | Report metadata and download IDs |

## Upgrade safety

Migration **0006** clears legacy Gitleaks raw secret values in PostgreSQL and intentionally cannot be reversed to reconstruct secrets. It **does not** purge old report files, object storage or backups. Rotate any real exposed secrets before or during remediation.

Migration **0007** adds `pipeline_jobs.mode`. Existing queued jobs preserve **patch mode**, avoiding silent changes to previously accepted instructions; newly enqueued jobs and scheduled scans use **scan mode** by default.

Back up PostgreSQL before applying migrations. For production, test the migration against a staging copy and validate `alembic_version` and the new queue column.

## Raw reports

Trivy raw report JSON is retained for audit. Gitleaks raw Secret/Match/Line data is redacted for new reports and removed from legacy PostgreSQL records by migration 0006. Authentication and Project authorization apply to downloads.

Do not expose the database directly to users or an unrestricted AI agent. The optional MCP integration requires a separate SELECT-only account and provides global analytics, not per-user RBAC.
