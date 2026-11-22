# AppSec Control Center

A self-hosted security workflow for container images and Git repositories: scan real images with Trivy, generate CycloneDX SBOMs, evaluate security policies, scan repositories with Gitleaks, and review findings from one web interface. **No fake data, no preloaded demonstration, and no automatic image modification.**

AppSec uses Docker Compose v2, PostgreSQL, FastAPI, a background worker and a built-in responsive UI. Grafana, Metabase, Harbor/Copa patching and MCP are advanced or optional integrations.

> **Status:** Active development. Static tests and CI validation are available, but end-to-end production acceptance (registry, patching, database upgrade and browser access) is not yet complete. See [security review](docs/security-review.md) and [production roadmap](docs/production-roadmap.md).

## Quick start — the recommended path

**Prerequisites:** Linux or WSL2 with Docker Engine/Docker Desktop, Docker Compose **v2**, Git and Python 3.10+. Docker daemon access and permission to run containers are required. Allow access to configured image registries and vulnerability feeds, or use internal mirrors in isolated networks.

```bash
git clone https://github.com/sysmrk/AppSec-docker.git
cd AppSec-docker

# If testing this upgrade before merge:
git switch security/optional-mcp-hardening

./appsec setup
./appsec start
./appsec doctor
```

Open **http://127.0.0.1:8080**. The URL redirects to the AppSec Control Center login. The initial username is **admin**. `./appsec setup` creates random passwords/API keys in `.env` with local file permissions; it does not overwrite an existing deployment.

To display the generated login password on a trusted interactive terminal:

```bash
./appsec credentials
```

**Do not commit `.env` to Git.** For remote deployments use authenticated HTTPS, update `GRAFANA_ROOT_URL`, and set `APPSEC_SESSION_COOKIE_SECURE=true`. The default web listener is bound to server loopback only, not accessible directly from other computers. Use an approved reverse proxy or SSH tunnel.

## Your first real scan

In the web UI, choose **Scan image**, enter the full container reference (e.g. an internal registry name and version), optionally choose a Project, then click **Start image scan**.

By default, AppSec performs:

```text
Image -> Trivy -> Vulnerability report + SBOM -> Policy gate -> Stored results
```

It does **not** patch or push an image. The operation is asynchronous; open **Overview** to see the job and **Results** to see severity counts, individual CVEs, policy status and authenticated downloads. Repository secret scanning is available under **Scan repository**; the Git host must be explicitly allowed.

All dashboards show **real PostgreSQL data**. A newly installed instance correctly shows empty lists until a scan runs.

## Main commands

| Command | Purpose |
| --- | --- |
| `./appsec setup` | Generate secure initial `.env` (preserves existing config) |
| `./appsec start` | Start scan-only platform and apply DB migrations |
| `./appsec doctor` | Check Docker, Compose, containers, credentials and API/DB health |
| `./appsec status` | See container status |
| `./appsec logs worker` | Inspect worker logs |
| `./appsec stop` | Stop services; named data volumes are preserved |
| `./appsec credentials` | Reveal admin credentials on a trusted interactive terminal |
| `./appsec start --analytics` | Also enable Metabase |
| `./appsec start --patching` | Explicitly enable privileged BuildKit and patch/push capability |

Existing advanced CLI operations remain accessible under `./scripts/appsecctl.sh` and the FastAPI API.

## Advanced features are opt-in

**Patch and registry push:** By default this feature is disabled. Configure your registry and credentials first (see [registry guide](docs/registry.md)), then run `./appsec start --patching`. In the web UI, enable **Show advanced options**, choose **Scan + Patch + Push + Rescan**, and explicitly confirm. This path uses privileged BuildKit; use only isolated, trusted executors. The option is unavailable in the UI while the server has patching disabled.

**Analytics:** Grafana remains available at **http://127.0.0.1:8080/grafana/**. Metabase is optional: `./appsec start --analytics`, then **http://127.0.0.1:3001**.

**MCP / AI:** Off by default and never required for normal setup. `make mcp-up` starts a separate, read-only MCP service on `127.0.0.1:8091/mcp`. Connect compatible local AI clients via STDIO, or use MCP Inspector. Complete instructions: [MCP guide](docs/mcp.md). Remote AI clients require a separate authenticated HTTPS/OAuth gateway.

## Important upgrade notes

For existing installations moving from the old pipeline:

1. Back up the database, reports and relevant object storage before upgrading.
2. New image jobs run **scan-only** by default; a new patch job requires `mode=patch` and explicit `confirm_patch=true`. Already queued pre-upgrade jobs retain patch behavior for compatibility; review queued jobs before allowing workers to start.
3. `./appsec start` runs migrations 0006/0007 automatically. Migration 0006 clears historical secret-bearing fields in PostgreSQL but **does not** scrub old HTML/JSON reports, MinIO/S3 artifacts or backups; rotate exposed credentials and purge old copies.
4. All downloads now require authentication and project-scoped authorization. Old Grafana root URLs change to `/grafana/`; new Control Center uses `/`.
5. Local HTTP development sets `APPSEC_SESSION_COOKIE_SECURE=false` only because the default listener binds to `127.0.0.1`. Enable secure cookies for HTTPS.
6. Repository targets are restricted to exact HTTPS hostnames in `SECURITY_ALLOWED_GIT_HOSTS`.
7. The UI deliberately does not include a demo mode or synthetic results.

## Documentation

| Document | Contents |
| --- | --- |
| [Quick start and user guide](docs/user-guide.md) | First login, scan, results, downloads, UI navigation |
| [Installation and operations](docs/operations-runbook.md) | Setup, upgrades, diagnostics, production configuration |
| [Architecture](docs/architecture.md) | API, queue, worker, storage, security boundaries |
| [Workflow](docs/workflow.md) | Scan-only and optional patch execution |
| [API guide](docs/api-guide.md) | Authenticated REST API and job operations |
| [CI/policy guide](docs/ci-policy-guide.md) | CI/CD gate and exit codes |
| [Registry guide](docs/registry.md) | Optional Harbor/Copa/BuildKit |
| [Database](docs/database.md) | Schema and migration lifecycle |
| [MCP guide](docs/mcp.md) | Optional AI connectors and results |
| [Security review](docs/security-review.md) | Fixed findings and residual risks |
| [Production roadmap](docs/production-roadmap.md) | Remaining enterprise controls |

This application is **not** a substitute for verifying images/signatures, secure registry credentials, runtime isolation or organization-specific security policy.
