# AppSec Architecture

## User-facing entrypoint

The default entrypoint is **AppSec Control Center** at `http://127.0.0.1:8080/`, a responsive first-party UI served by the existing FastAPI process behind Nginx. No frontend build stack, external CDN or sample data is required. The UI consumes authenticated, Project-aware read endpoints and creates jobs using the existing API.

Grafana is an advanced monitoring integration under `/grafana/`. Metabase uses a separate optional service at `:3001`. MCP is a separate optional read-only integration.

## Default image scan (no patch/push)

```text
Browser/UI or CLI -> FastAPI auth + RBAC -> PostgreSQL pipeline_jobs (mode=scan)
                                         |
                                         v
                                      Worker
                                         |
                                  Docker -> Trivy
                                         |
                                 Findings + SBOM
                                         |
                                      Policy
                                         |
                             Postgres / MinIO reports
                                         |
                               UI Results / Downloads
```

**Important:** the worker uses Docker Socket to start Trivy, but **BuildKit is not started by default**. The initial image scan is read-only with respect to the image registry. Scans may download images and CVE databases to local caches.

## Explicit advanced patch path

Only after `./appsec start --patching`, registry configuration, and an explicit browser/API confirmation:

```text
Original Trivy scan -> Copa + privileged BuildKit -> Push patched image to registry
          -> Patched Trivy scan + SBOM -> diff -> policy -> authenticated reports
```

Patching failures are recorded; no fake success is generated. Worker Docker Socket and BuildKit privileged access are powerful and must be isolated before production.

## Components

| Component | Responsibility |
| --- | --- |
| Nginx | Loopback-only ingress, routes root UI, `/appsec-api/`, Grafana `/grafana/` |
| FastAPI | Login/session, REST API, authorization, UI static assets, job creation |
| PostgreSQL | Users, roles, projects, queue, scan findings, policies, reports |
| Worker / Scheduler | Asynchronous processing and scheduled image scans |
| Trivy | Image vulnerability scan and CycloneDX SBOM |
| Gitleaks | Repository secret scanning with persisted secret redaction |
| MinIO | S3-compatible report storage (default local deployment) |
| Grafana | Advanced monitoring |
| Metabase | Optional business analytics |
| BuildKit + Copa | Optional and privileged patch/push executor |
| MCP Adapter | Optional read-only analytics for AI clients; no mutation tools |

Worker uses `FOR UPDATE SKIP LOCKED` for job claiming. Each image job has a mode (`scan` default or `patch` explicit), UUID, status, timestamps and output pipeline reference. Report downloads require valid session/API identity and authorized Project access.

## Trust boundaries

- The API must not mount Docker Socket; workers currently do, even during scan-only use.
- The local UI authenticates via AppSec API sessions. Remote access requires HTTPS and identity-aware proxy.
- MCP uses a separate container, no Docker Socket, and should use a SELECT-only PostgreSQL role. Current MCP queries provide global analytics and do not impersonate AppSec end users. See [MCP documentation](mcp.md).
- Secrets from Gitleaks must never be copied into returned findings. Historic artifacts from pre-hardening installations require cleanup.

See [security review](security-review.md) and [production roadmap](production-roadmap.md).
