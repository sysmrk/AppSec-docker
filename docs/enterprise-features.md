# Enterprise Features — AppSec Control Center

The first-party **Administration** screen is intended to handle common operations without writing SQL or building a CI/CD pipeline.

## Users, teams, projects, and policy

An administrator can create Users, Teams and Projects; assign a user to a Team with a role of `owner`, `maintainer`, `member`, or `viewer`; and create Project-level vulnerability policies using Critical/High/Medium/Low thresholds. The UI generates each new user's random API key and shows it once. Treat it as a credential and store it only in a secret manager.

The **New manual scan** screen accepts a real image reference and launches scan-only. **My workflows** then presents the CVEs, SBOM and policy result and requires explicit human consent before any optional registry Patch/Push. The `approve_patch` decision needs Operator/Admin privileges and Project write permissions. A Project-scoped workflow is visible only to current Team members; an unassigned manual workflow belongs to its creator/admin.

Use the existing REST API for automation; never hard-code keys like the old `appsec-dev-key` sample. Export your real key in a secure session:

```bash
export APPSEC_API_KEY='REPLACE_WITH_GENERATED_KEY'
curl -X POST http://127.0.0.1:8080/appsec-api/api/teams \
  -H "X-API-Key: ${APPSEC_API_KEY}" -H 'Content-Type: application/json' \
  -d '{"name":"Platform Security"}'

curl -X POST http://127.0.0.1:8080/appsec-api/api/projects \
  -H "X-API-Key: ${APPSEC_API_KEY}" -H 'Content-Type: application/json' \
  -d '{"name":"Core AppSec","slug":"core-appsec","team_id":"TEAM_UUID"}'
```

API details: [API Guide](api-guide.md). Full human approval sequence: [Workflow Guide](workflow.md).

## Artifact storage and secrets

The normal local installation starts MinIO for S3-compatible report storage. `./appsec setup` generates random MinIO credentials in `.env`. Do **not** use the old sample password for real installations. Before production, replace the local root-level credentials with a bucket-limited service account and keep values in a real secrets manager.

Configuration keys (replace placeholders with approved secrets):

```env
ARTIFACT_STORAGE=s3
S3_ENDPOINT_URL=http://minio:9000
S3_BUCKET=appsec-artifacts
S3_ACCESS_KEY_ID=YOUR_SERVICE_ACCOUNT
S3_SECRET_ACCESS_KEY=YOUR_SECRET_VALUE
```

Reports are generated locally and can be uploaded to S3-compatible storage. All downloads require valid AppSec identity and Project authorization. A database migration cannot purge already generated historical S3 reports or backups; rotate leaked credentials and remove old copies.

## Analytics vs operator workflows

**Metabase** is the single dashboard system; Grafana has been removed. The Metabase views cover image CVEs, policy outcomes, manual workflows, pending approvals and vulnerability trends. **Approvals must happen in Control Center, not Metabase.** Metabase has separate authentication and currently exposes aggregate data across Projects; restrict accounts and use a database SELECT-only role where feasible.

**MCP / AI** is optional and read-only. It cannot perform scans, make authorization decisions, patch or push images.

## Enterprise production gates

Open requirements include hardened worker isolation from Docker Socket, privileged BuildKit isolation, OIDC SSO/MFA, CSRF review, rate limiting, image digest pinning/signing, least-privilege Metabase and S3 credentials, verified backup/restore and complete Docker/Harbor/Copa/browser end-to-end acceptance tests. See [Security Review](security-review.md) and [Production Roadmap](production-roadmap.md).
