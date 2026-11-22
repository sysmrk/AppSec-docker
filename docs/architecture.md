# Architecture

## Primary user experience

\`\`\`text
Browser -> Nginx :8080 -> FastAPI /ui + /api/*
                              |
                         Auth + RBAC
                              |
                       PostgreSQL (jobs)
                              |
                       Worker / Scheduler
                              |
              Trivy scan + CycloneDX SBOM + Policy
                              |
                   Postgres / MinIO reports
                              |
                  Browser review + approval
                              |
                  (optional) Copa + BuildKit
                              |
                      Registry Push -> Rescan -> Diff
\`\`\`

The browser UI is a first-party, static HTML/CSS/JS application served by FastAPI. No separate frontend build or demo dataset. It uses authenticated API calls; user-supplied fields are inserted via DOM text nodes rather than raw HTML.

## Manual approval boundary

\`manual_workflows\` stores the requesting user, image, optional Project, scan job, optional patch job, decision, reviewer and timestamp. Before approval, the only worker mode is **scan**. After completed original scan and policy, a user with appropriate role and Project write access may finalize the review or create a **single-attempt** \`continue_patch\` job. The worker reuses the existing pipeline's original scan, rather than starting an unrelated new scan.

API requires \`APPSEC_PATCH_ENABLED=true\`, \`confirm_push=true\`, a persisted decision and an authenticated Operator/Admin. Worker independently enforces patch opt-in. The continuation job intentionally has no automatic retry after possible partial registry write.

## Core services

| Service | Role |
| --- | --- |
| Nginx | Loopback-only routing from \`/\` to Control Center and \`/appsec-api/\` to FastAPI |
| FastAPI | Authentication, API, UI, Project access and manual decisions |
| PostgreSQL | Project/user records, queues, image scans, manual workflow and audit history |
| Worker | Runs Trivy, generates SBOM and optional Copa continuation |
| Scheduler | Schedules image scans |
| MinIO | Optional S3-compatible artifact backing (enabled in normal local deployment) |
| Metabase | **Only** analytics system, three dashboards; accessible at local \`:3001\` |
| BuildKit | Privileged **opt-in** patch executor |
| MCP | Optional independent read-only adapter for AI; no mutation tools |

Grafana is intentionally **absent**. The web UI handles manual operations and approval, while Metabase handles aggregated charting. Metabase's own account system must be access-controlled independently and is not equivalent to AppSec Project-scoped RBAC.

## Security boundaries

- API never mounts Docker Socket. Worker currently mounts it to execute Trivy and optional Copa; use isolated workers before production.
- Manual workflows are creator/admin-private when unassigned, or visible to current Project Team members. Only authorized operators can approve changes.
- Project-scoped scan/report APIs require membership; downloads always require authenticated AppSec credentials.
- MCP has no Docker Socket, no write tools and only parameterized queries, but provides **global** analytics to its authorized caller. It requires network isolation and read-only DB credentials.
- All image and approval results derive from real database records. No demo/mock data is generated.
