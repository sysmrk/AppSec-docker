# Operations Runbook

## Installation: first start

Requirements: Linux/WSL2, Docker with Compose v2, Git, Python 3.10+, a real registry/image source, network access or internal mirrors for Trivy databases.

\`\`\`bash
git clone https://github.com/sysmrk/AppSec-docker.git
cd AppSec-docker
./appsec setup
./appsec start
./appsec doctor
\`\`\`

This uses \`main\`. The setup creates \`.env\` with random credentials, never overwrites an existing one and does **not** add sample data. Start runs migrations and brings up PostgreSQL, MinIO, FastAPI, Nginx, Worker, Scheduler and **Metabase**. Grafana has been removed. Privileged BuildKit and MCP stay off unless explicitly requested.

AppSec UI: \`http://127.0.0.1:8080\`. Metabase UI: \`http://127.0.0.1:3001\`. Obtain both initial credentials with \`./appsec credentials\` (trusted interactive terminal).

## Operations

\`\`\`bash
./appsec status
./appsec doctor
./appsec logs api
./appsec logs worker
./appsec logs scheduler
./appsec logs metabase
./appsec stop
\`\`\`

\`make init\`/\`make up\` remain compatibility aliases; \`make mcp-up\` is the optional read-only AI integration. Metabase dashboards are provisioned by \`scripts/setup-metabase.sh\`, automatically invoked on each startup (idempotent card/dashboard lookup).

## Manual workflow state

The UI queues a regular \`scan\` job and saves a row in \`manual_workflows\`. A worker executes Scan + SBOM + Policy + Report. On successful completion, the row becomes **awaiting_approval**. Operator can **finish** or **approve_patch** from the UI. Approval creates a \`continue_patch\` job bound to the **existing pipeline ID**, with \`max_attempts=1\`. The worker enforces \`APPSEC_PATCH_ENABLED=true\`; otherwise it rejects the job. The saved decision and approving identity are audited.

## Optional patch and registry writes

\`\`\`bash
./appsec start --patching
\`\`\`

Use only on an approved isolated host. Configure registry authentication as in [registry guide](registry.md). The control center still requires two explicit UI acknowledgments. No default auto-Push.

## Existing deployment upgrade

1. Back up PostgreSQL, reports, S3/MinIO artifacts and current \`.env\`.
2. Inspect **existing queued Patch jobs**: historical jobs may retain their previous mode. Workers reject writes while \`APPSEC_PATCH_ENABLED=false\`, but review them before re-enabling patching.
3. Update the reviewed release on \`main\`. Run \`./appsec start\` to apply Alembic migrations through 0009.
4. Verify admin login, Project RBAC, manual scanning, approval, report downloads and Metabase dashboards. Test any live migration first in staging.
5. If upgrading an old \`.env\`, supply a strong \`METABASE_ADMIN_PASSWORD\` (at least 16 characters) and correct \`METABASE_ADMIN_EMAIL\`; do not rely on old hard-coded values.
6. Remove obsolete Grafana URLs, containers and configuration. **Do not automatically delete the old Grafana Docker volume**, because it might hold data the operator wants to export.
7. Previous Gitleaks file/S3/backups may contain raw secrets. Rotate compromised credentials and remove old copies; migration 0006 sanitizes only PostgreSQL fields.
8. Enable secure session cookies when serving HTTPS: \`APPSEC_SESSION_COOKIE_SECURE=true\`. Restrict Metabase and AppSec endpoints to approved identity-aware network access.

## Health and monitoring

\`./appsec doctor\` checks actual Docker, Compose, containers, API, database and Metabase HTTP health. Admin-only **System health** uses worker/scheduler heartbeat timestamps stored in PostgreSQL. A stale timestamp can indicate a busy worker, not necessarily a failed container.

Metabase provides three preconfigured analytics dashboards; see [Metabase guide](metabase.md). SQL reports are **read-only** and are not an approval mechanism.

## Production considerations

- Worker Docker Socket and privileged BuildKit are sensitive execution interfaces; isolate workers.
- Rotate all bootstrap passwords; use an enterprise secret manager.
- Put a hardened authenticated TLS reverse proxy in front of any remote access; default listeners bind only to loopback.
- Scope registry credentials to permitted namespaces; sign and promote images through your established controls.
- Test backup/restore, rollback, CVE-feed freshness, S3 retention, CSRF, rate limits and multi-tenant RBAC before production approval.
- MCP stays optional and requires a SELECT-only DB role plus strong remote authentication.
