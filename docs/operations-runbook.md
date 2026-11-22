# Installation and Operations Runbook

For the recommended first-run flow, see [README](../README.md) and [user guide](user-guide.md).

## Prerequisites

- Linux/WSL2 with Docker Engine or Docker Desktop, Docker Compose v2, Git, Python 3.10+
- Network access (or configured internal mirrors) for images and Trivy vulnerability database
- Sufficient disk space for images, reports, Docker volumes and PostgreSQL
- Dedicated trusted worker host for production (Docker Socket remains powerful)

## Fresh installation (no demonstration data)

```bash
git clone https://github.com/sysmrk/AppSec-docker.git
cd AppSec-docker
# For the PR before merge: git switch security/optional-mcp-hardening
./appsec setup
./appsec start
./appsec doctor
./appsec credentials
```

Open `http://127.0.0.1:8080` on the host. The CLI generates random credentials in `.env` (mode 0600) and applies migrations automatically. It **never overwrites an existing `.env`**.

The default startup launches PostgreSQL, MinIO, API, Nginx, a shared Worker, Scheduler and Grafana. It does **not** start privileged BuildKit, Metabase or MCP. No Registry/Harbor is required for scan-only mode. External vulnerability DB downloads may still be needed.

## CLI operations

```bash
./appsec start                 # Scan-only
./appsec start --analytics     # Also start Metabase
./appsec start --patching      # Opt-in privileged BuildKit and patch mode
./appsec status
./appsec doctor
./appsec logs worker
./appsec stop
```

`make up` and `make init` remain compatibility shortcuts for the platform with analytics. For advanced CLI actions: `./scripts/appsecctl.sh`. MCP remains optional: `make mcp-up` and `make mcp-down`.

## Restore/upgrade an existing deployment

1. Back up Postgres and reports/object storage. Review queued jobs: migration 0007 preserves previously queued jobs as patch mode.
2. Preserve `.env` and stored secrets. `./appsec setup` does not reset existing accounts.
3. Pull reviewed code changes, then run `./appsec start` to apply migrations. **Production deployments require staging migration testing**.
4. Migration 0006 redacts historical secret-bearing PostgreSQL data but does not scrub old JSON/HTML/S3 objects or backups. Rotate exposed credentials and purge old copies.
5. Session cookie is Secure for HTTPS, false only for localhost HTTP. All downloads require authentication; Grafana root is now `/grafana/`.
6. Test login, create a scan-only job, verify policy result, download reports and inspect service health.

## Diagnostics

```bash
./appsec doctor
./appsec status
./appsec logs api
./appsec logs worker
./appsec logs nginx
curl -fsS http://127.0.0.1:8080/appsec-api/health
```

The doctor checks actual local Docker/Compose/container state and API/DB reachability, reports failures and warnings, and does not generate test scans.

For reverse proxy/remote use: keep AppSec loopback-only or inside a trusted network, terminate TLS at an approved external proxy, restrict ingress, and set `APPSEC_SESSION_COOKIE_SECURE=true`, `GRAFANA_ROOT_URL=https://your-host/grafana/`.

## Optional analytics, registry patching and MCP

- Grafana: `http://127.0.0.1:8080/grafana/`, admin login configured in `.env`
- Metabase: `./appsec start --analytics`, URL `http://127.0.0.1:3001`
- Harbor and Copa: [registry.md](registry.md). Patch/Push must be explicitly enabled using `./appsec start --patching`. Avoid running privileged BuildKit on sensitive hosts.
- AI/MCP: [mcp.md](mcp.md). MCP does not start with the normal platform, is read-only and requires proper OAuth/TLS for cloud clients.

## Security and operational warnings

- Worker retains powerful Docker Socket access even in scan-only mode. Isolate workers, set egress policy and do not scan untrusted images on sensitive hosts.
- Do not expose PostgreSQL/MinIO/BuildKit or docker.sock externally.
- `.env` holds sensitive values; use an approved secret manager for production and never commit it.
- Local S3 credentials generated at setup match the MinIO root secret. Replace with a bucket-scoped MinIO service account before production.
- Old report URLs must not be treated as credentials; all report downloads need an authenticated AppSec session or API key.
- Existing global/unassigned Project data remains shared with all authenticated AppSec accounts.
- Keep image/scanner signatures and version digest pinning under review.


## System health page

An administrator can open **System health** in the web UI to inspect real queue counts and Worker/Scheduler heartbeat times (migration 0008). The UI does not get Docker Socket access. If heartbeat timestamps are old, check `./appsec doctor` and `./appsec logs worker`; a long-running scan can temporarily prevent heartbeat updates.
