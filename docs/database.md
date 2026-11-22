# AppSec Database Schema and Migrations

PostgreSQL stores source image references, `images`, `pipeline_runs`, `scan_runs`, `vulnerabilities`, `artifacts`, `policy_results`, `patch_runs`, `scan_diffs`, `pipeline_jobs`, `manual_workflows`, `users`, `teams`, `team_members`, `projects`, `service_heartbeats`, `registry_connections`, `mfa_recovery_codes`, audit logs and generated reports.

## Recent Alembic revisions

| Revision | Change |
| --- | --- |
| 0006 | Redact historical Gitleaks secrets in **DB** (does not purge files/S3/backups) |
| 0007 | Scan-only default for new jobs, preserve old queued patch instructions |
| 0008 | Worker/Scheduler heartbeat table |
| 0009 | Manual workflow approval and one-time patch continuation |
| 0010 | User lifecycle: lockout, password rotation, disable and session/API key audit |
| 0011 | Separate prepared patch from final Registry publication approval and job |
| 0012 | Registry metadata and image inventory indexes |
| 0013 | Encrypted TOTP MFA and hashed single-use recovery codes |

The baseline `db/schema.sql` and versioned Alembic upgrades aim to support fresh installs and existing DBs; test the exact old schema state in staging. `./appsec start` runs `alembic upgrade head` through the standard runner.

## Manual workflow transactions

`manual_workflows` binds creator, Project scope, initial scan job, optional patch preparation job and separate publish job. Decisions and approving identity/time are persisted. Final publication is permitted only with prepared image, final passed Policy and registered authorized destination, and only a one-attempt publication job is queued. Optimistic UI state is not authorization; the backend locks the workflow and checks membership/role at the time of approval.

`patch_runs` records local image reference, publication state and timestamp. States may be `prepared`, `publishing`, `published`, or `uncertain`; ambiguous Push failures must be reconciled outside automatic retries.

## Security / backup

Session tokens and API keys are hashed in the DB. Passwords use salted PBKDF2. TOTP secrets are Fernet-encrypted with a separate operator-managed environment key, while backup/recovery codes are hashed. Back up that encryption key separately from PostgreSQL and test full restore. Account revocation, Team membership and role changes are audited and should be monitored.

Metabase's own application DB is separate; it uses a distinct login and global analytics view. Use a dedicated SELECT-only role for application data access in sensitive deployments.
