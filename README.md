# AppSec Control Center

**Container and repository security for humans and CI/CD.** Scan actual registry images with Trivy, generate CycloneDX SBOMs, check policy, inspect CVEs and reports, and optionally patch/push through Copa. Use the built-in guided web UI or the existing CLI/API. Everything is backed by real PostgreSQL data: **there is no demo mode or synthetic result generation.**

**Analytics:** Metabase is the only dashboard product. Startup provisions three dashboards: **AppSec Security Overview**, **AppSec Manual Operations**, and **AppSec Vulnerability Trends**. Grafana has been removed. **AI/MCP** remains completely optional.

> Status: development release. GitHub Actions tests syntax, unit contracts, DB migrations, manual workflow transactions, and analytics SQL. A production-like Docker/Harbor/Copa/browser end-to-end signoff is still required. See [Security Review](docs/security-review.md).

## Quick start (no CI/CD needed)

Requirements: Linux or WSL2, Docker Engine or Docker Desktop, **Docker Compose v2**, Git, Python 3.10+, reachable registry images and access to the Trivy vulnerability database (or configured internal mirrors).

\`\`\`bash
git clone https://github.com/sysmrk/AppSec-docker.git
cd AppSec-docker
./appsec setup
./appsec start
./appsec doctor
\`\`\`

Open **http://127.0.0.1:8080** on the host. Your local admin username is \`admin\`; use \`./appsec credentials\` in a trusted interactive terminal to view the initial password. The same command shows Metabase login details. Do not paste or commit secrets.

\`./appsec setup\` generates random passwords and API keys in \`.env\` with mode 0600, without overwriting existing credentials. \`./appsec start\` applies database migrations and starts API, Worker, Scheduler, MinIO, Nginx **and Metabase**, then provisions real analytics dashboards. No images or findings are preloaded.

For remote access, use an approved HTTPS proxy and set \`APPSEC_SESSION_COOKIE_SECURE=true\`. The default web listeners bind to **127.0.0.1**, not the public Internet.

## Manual image workflow — fully in the browser

1. Sign in and select **New manual scan**.
2. Enter an **image reference** available to the worker's registry credentials, such as \`registry.example.org/team/api:1.4.0\`; choose a Project if applicable.
3. Click **Start guided scan**. The job runs Trivy → SBOM → Policy → Report, without any image modification.
4. Open **My workflows** to follow queued, running and completed steps. Review vulnerabilities, policy results and downloadable files.
5. At **Awaiting approval**, choose **Finish without patching**, or, only if an administrator explicitly enabled patching, check the registry-write acknowledgement and **Approve patch + registry push**.
6. On approval, the worker continues the **same pipeline**, using its original scan to run Copa → Push → Patched Rescan → SBOM → CVE Diff → Final Policy/Report. This stage is queued once; there is no automatic retry of a potentially non-idempotent registry push.
7. See progress and results in the same workflow. User identity, decision and time are stored for audit.

The UI accepts **image references**, not Docker tar uploads. For local-only images, load the image on the scanning worker or push it to an approved registry before starting. No CI/CD pipeline is required.

Repository scans are available in **Scan repository** and use Gitleaks with redacted findings. Administrators can use **Administration** for teams, projects, users, membership and severity-threshold policies. Viewers can inspect only permitted data, not start scans.

## Common commands

| Command | Function |
| --- | --- |
| \`./appsec setup\` | First-run secure configuration, preserves existing \`.env\` |
| \`./appsec start\` | Start scanning platform **and Metabase** |
| \`./appsec doctor\` | Diagnose Docker, Compose, containers, API/DB and Metabase |
| \`./appsec status\` | Check actual containers |
| \`./appsec logs worker\` | Inspect scanner problems |
| \`./appsec credentials\` | View AppSec/Metabase admin credentials locally |
| \`./appsec stop\` | Stop services without deleting named volumes |
| \`./appsec start --patching\` | **Explicitly** enable privileged BuildKit and registry-write workflow |
| \`make mcp-up\` / \`make mcp-down\` | Opt-in read-only AI MCP service |

Metabase runs at **http://127.0.0.1:3001**. Sign in using the credentials created by \`setup\`. Dashboards are saved and can be expanded there; the Control Center remains the recommended interface for actual security operations and approvals.

For automated CI/CD, \`./scripts/appsecctl.sh ci image "$IMAGE_REF"\` or the \`POST /appsec-api/pipelines\` REST endpoint remain supported; both use scan-only defaults. The old one-shot Patch+Push path is advanced and must be selected explicitly.

## Safety and upgrades

- Privileged **BuildKit is off by default**. The Worker still has Docker Socket access to run Trivy and is a high-trust component: isolate it from sensitive workloads.
- Workflow approvals are persisted and require operator/admin privileges and Project write access. A manual workflow in a Project is visible to current team members; an unassigned workflow is visible only to its creator and admins.
- Before upgrading existing deployments, back up PostgreSQL and object storage, inspect queued legacy Patch jobs and test migrations. Migration **0009** adds manual workflow state and a one-time continuation mode.
- Historical Gitleaks exports/files/S3 objects/backups may contain secrets. Rotate exposed credentials and remove old stored copies; database redaction cannot purge old files.
- Metabase authentication is independent of AppSec accounts. Restrict access: it is a **global analytics** view, not per-Project RBAC. Do not publish the Metabase port without identity controls.
- Grafana is **no longer included or started**. Its previously existing Docker volume is not automatically deleted (to avoid data loss).
- Release policy: changes are committed directly to \`main\`. GitHub Actions creates an annotated **\`change-<SHA>\` tag for every main commit**, plus semantic release tags from \`VERSION\`.

## Documentation

| Guide | Contents |
| --- | --- |
| [User Guide](docs/user-guide.md) | Manual UI, approvals, CVE reports, administration |
| [Operations Runbook](docs/operations-runbook.md) | Install, migrate, monitor and troubleshoot |
| [Workflow](docs/workflow.md) | Scan, review, approve, patch, rescan, finish |
| [Architecture](docs/architecture.md) | API, Worker, queue, permissions and dependencies |
| [Metabase analytics](docs/metabase.md) | Three dashboards, provisioning and access |
| [API](docs/api-guide.md) | REST endpoints, sessions and automation |
| [CI and Policy](docs/ci-policy-guide.md) | Scan gates and pipeline integration |
| [Registry](docs/registry.md) | Optional Harbor/Copa/BuildKit patching |
| [Database](docs/database.md) | Tables, workflows, migration versions |
| [Optional MCP](docs/mcp.md) | Local AI, Inspector, secure remote access |
| [Security Review](docs/security-review.md) | Fixed and remaining risks |
| [Production Roadmap](docs/production-roadmap.md) | Open production gates |
