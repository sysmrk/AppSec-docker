# Operations runbook — v2

## Installation

Use a dedicated trusted Linux/WSL2 host with Python 3.10+, Git, Docker Engine and Compose v2 or later compatible plugin. Ensure sufficient storage and access to approved runtime and bootstrap images, scanner DBs, package repositories and release endpoints. Do not run a Docker-socket worker beside sensitive production workloads.

```bash
git clone https://github.com/sysmrk/AppSec-docker.git
cd AppSec-docker
./appsec setup
./appsec start
./appsec doctor
./appsec credentials
```

Alternatively ./appsec wizard prompts for confirmation. Setup preserves existing .env; use chmod 600 .env and retain the encryption key. Full startup always includes BuildKit, builds the migration runner, applies schema upgrades, starts API/worker/scheduler/Nginx/Metabase, verifies runtime source fingerprints and patch flags. Optional MCP and Harbor are separate. The local UI is http://127.0.0.1:8080 and Metabase http://127.0.0.1:3001. For remote deployment configure TLS and APPSEC_SESSION_COOKIE_SECURE=true; local HTTP is not a production endpoint.

## Configuration

Use .env.example for supported variables and .env.production.example as a hardened starting point, not an automatic production deployment. Never overwrite an existing .env with a template. Bootstrap image variables and docker-compose.override.yaml handle restricted networks; database-backed pull sources cannot resolve images before PostgreSQL exists. For strict runtime source enforcement set APPSEC_REQUIRE_IMAGE_SOURCES=true only after configuring suitable sources. Set SECURITY_ALLOWED_GIT_HOSTS for approved private Git hosts. Configure valid package sources and signing keys separately.

## Upgrade

1. Drain active image/security jobs and reconcile uncertain publications. Stop services; do not remove volumes.
2. Back up PostgreSQL, report volume, MinIO/S3, .env and override, encryption key and tool-updates volume. Preserve required local Docker images.
3. Fetch and fast-forward the tested revision (or use the release tag). Preserve uncommitted local changes; never reset blindly.

```bash
./appsec stop
git fetch origin main --tags
git merge --ff-only origin/main &&
  ./appsec start &&
  ./appsec doctor
curl -fsS http://127.0.0.1:8080/appsec-api/ui/build-info
```

Check Alembic 0018_tool_updates and actual browser build. The CLI verifies the source of API, worker and scheduler; browser assets are fingerprinted. If a merge fails, stop and resolve it. If migration fails, inspect the migration runner and database before restarting; do not drop data.

## Diagnose

```bash
./appsec status
./appsec doctor
docker compose logs --since=30m --tail=100 worker
docker compose logs --since=30m --tail=100 scheduler
docker compose top worker
docker compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
```

```sql
SELECT id, requested_image, mode, status, attempts, started_at, finished_at,
       COALESCE(finished_at, now()) - started_at AS elapsed, last_error
FROM pipeline_jobs ORDER BY created_at DESC LIMIT 10;
SELECT image_ref, phase, status, started_at, finished_at, error_message
FROM scan_runs ORDER BY started_at DESC LIMIT 10;
SELECT version_num FROM alembic_version;
```

Use finished_at - started_at for completed duration; now() - started_at overstates elapsed after completion. Log events IMAGE_SOURCE_TRY/SELECTED/FAILED and SCAN_STAGE_START/DONE/FAILED distinguish pull, DB, scan and SBOM. Default pull timeout is 180s per source; APPSEC_TRIVY_DB_TIMEOUT_SECONDS=180 per DB repository, APPSEC_TRIVY_SCAN_TIMEOUT_SECONDS=900, APPSEC_SBOM_TIMEOUT_SECONDS=600. Scanner timeout cleanup targets its uniquely named container. Inspect SCAN_CLEANUP_FAILED manually. Worker processes queues serially in default topology; stale heartbeats may mean busy, and interrupted jobs can require manual reconciliation. Never force retry a patch/push.

## Backups and recovery

Use pg_dump and an approved consistent object-storage/volume backup. Example database export (protect file permissions):

```bash
umask 077
docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > appsec-db.dump
```

Also back up Metabase application DB, storage objects and local evidence, encryption key, config, and tool-updates metadata/binaries. Store backups encrypted; test restore into an isolated staging environment. Restore against compatible release/schema; do not downgrade migrations blindly. Old Gitleaks copies may contain raw secrets; rotate and purge under retention policy.

## Publication and maintenance

Registry credentials must be provisioned in the worker Docker environment, not entered into registry metadata. For local export use docker save -o patched.tar EXACT_LOCAL_TAG on the same daemon. See [registry](registry.md). For tool update failures see [tool updates](tool-updates.md). The standalone Trivy DB updater uses deployment settings rather than the database-backed policy; use only if explicitly approved and configured to use the same cache.

./appsec stop preserves volumes. Never use down --volumes for routine upgrades. Production acceptance requires isolated execution, TLS, least privilege, image signing/pinning, backup/restore, full browser and registry E2E, SSO and analytics segmentation.

### v3 shared runtime image

Use `./appsec start` (or `make build` to build only). Only `appsec-runner` builds the local shared image, then migrations and services use the same image. Runtime service pull policy is `never`. If a local override previously defined separate API/worker/scheduler build options, move common build arguments under `appsec-runner.build.args` and preserve per-service environment/mounts. Do not run direct `docker compose up --build` on an uninitialized checkout; use the normal startup command. Do not run v2 and v3 concurrently on the same daemon; named resources can collide. Old image tags are not deleted automatically.
