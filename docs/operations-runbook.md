# Operations Runbook — installation and recovery

## Start without CI/CD

Prerequisites: Linux/WSL2, Docker Engine/Desktop with Compose v2, Git, Python 3.10+, registry image reachability and Trivy DB/mirror access.

```bash
git clone https://github.com/sysmrk/AppSec-docker.git
cd AppSec-docker
./appsec wizard
```

The wizard confirms a full startup including BuildKit, generates credentials and Fernet MFA key if `.env` is missing, then starts PostgreSQL, MinIO, API, Worker, Scheduler, Nginx and Metabase. **It never overwrites `.env`.** Alternative individual commands:

```bash
./appsec setup
./appsec start
./appsec doctor
./appsec credentials
```

AppSec UI: `http://127.0.0.1:8080`. Metabase: `http://127.0.0.1:3001`. Normal startup does not launch privileged BuildKit or the read-only MCP integration.

## Everyday operations

```bash
./appsec status
./appsec doctor
./appsec logs worker
./appsec logs api
./appsec logs scheduler
./appsec logs metabase
./appsec stop
```

Use Control Center **System health** to inspect live PostgreSQL heartbeat/queue information. A busy worker can have a stale heartbeat; use Docker `ps` and logs for deeper diagnostics. Error codes and corrective hints are described in [User Guide](user-guide.md).

## Prepare patch and publish

```bash
./appsec start --patching
```

Only run privileged BuildKit on isolated trusted workers. An Admin must register the exact destination HTTPS hostname in **Registries**, mark `allow_push` and separately configure Registry credentials on the Worker. The first approval creates a local prepared image and rescans; second approval publishes only after passing policy. To require distinct reviewers in an organization:

```env
APPSEC_REQUIRE_SECOND_APPROVER=true
```

If push fails, check Registry for a partially published tag/digest. Do not automatically retry. Local prepared images can be lost if the Docker host changes: a multi-host architecture needs worker affinity or a controlled staging registry and promotion.

## Identity and encryption

Human users can be disabled, reset, rotated or revoked in **Users & access**. New human users must change temporary passwords at first login. Optional MFA TOTP secrets are encrypted with `APPSEC_MFA_ENCRYPTION_KEY` (created on new `./appsec setup`). Back up this key separately from the DB; losing it makes existing enrolled TOTP secrets undecryptable. Existing installations upgrading from older versions must provision a Fernet key (32 random bytes base64 URL-safe) if enabling MFA.

Built-in MFA is not a replacement for enterprise OIDC/SSO. Metabase accounts and the optional MCP DB role are independent of AppSec user sessions.

## Upgrade / migration

1. Back up PostgreSQL, MinIO/S3 data, reports, credentials, MFA key and Docker volumes; test restore in staging.
2. Review old queued `patch` jobs; with patching disabled Worker refuses them, but enabling it later may allow historical jobs.
3. Update the tested version of `main` or checkout a release tag; run `./appsec start` to apply Alembic migrations.
4. Check schema revisions 0010 (user lifecycle), 0011 (separate publication), 0012 (registries/inventory), 0013 (MFA) and review the approved policy.
5. Verify login, first-password-change path, MFA enrollment/recovery, user disabling, Registry registration, manual scan, final publication approval and downloads in a staging environment.
6. Metabase is the only dashboard (Grafana removed previously). Existing Grafana volumes are preserved for manual cleanup if needed.
7. Old Gitleaks reports/S3/backups may contain secrets that DB migrations cannot remove. Rotate exposed credentials, purge old copies.

## Production limitations

- Worker mounts Docker Socket and optional BuildKit is privileged; isolate these workloads.
- Current built-in account management, TOTP and lockout are not external OIDC/LDAP/SAML federation.
- Metabase has a separate authentication model and global analytics; use a dedicated SELECT-only PostgreSQL role and restrict its network/user access.
- CSRF browser-write protection uses a custom header and SameSite cookies. Review full CSRF/session protection and rate limiting during security acceptance.
- Full Docker/Trivy/Copa/Harbor/browser E2E testing, backup/restore, HA and image digest/signature verification remain production gates.
- Browser GUI does not upload Docker TAR archives; it accepts Registry image references only.


## Trusted mirrors, operator reports and erasure

Open Registries to add approved mirror hostnames in numeric priority order. Test from the Docker daemon and from the separate Copa BuildKit execution context. A successful Docker pull is not proof that BuildKit can fetch the same reference. Use the consolidated Before/After report for actual scan comparison and post-fix recommendation. The initial scan never blocks on policy. For a local output choose Keep patched image locally; to export a tar on the same Docker host, run docker save -o patched.tar IMAGE_REF with the exact local tag shown in UI. For registry output enter the full registry/repository:tag and approve publication separately. Admin history deletion is irreversible for live DB and evidence but intentionally preserves audit logs, remote published images and backups.


## Upgrade: build the migration runner before applying Alembic revisions

The start command rebuilds appsec-runner from the current checkout before invoking migrate, then starts the API and workers. This prevents an existing cached runner from using stale migration files. Stop the previous platform and back up the database and evidence before upgrading. If a worker reports UndefinedTable for pending_image_removals, check the PostgreSQL alembic_version: revision 0015_history_purge must be present for this release. Rebuild the runner and run migrate before restarting the worker. Keep all data volumes. A restarting or stopped required worker is a doctor failure, not a healthy deployment.

Copa patch failures capture stderr and persist a bounded, sanitized diagnostic in the patch and job error. Existing historical failures are unchanged. Inspect worker and BuildKit logs and validate the executor, registry access and package repositories before submitting a new approved workflow; never retry an uncertain publication automatically.

Image pull attempts and scanner stage starts/finishes are logged without dumping full raw Trivy reports in the worker. Trivy DB prefetch attempts default to 180s per repository, scans to 900s and SBOM generation to 600s. Set APPSEC_TRIVY_DB_TIMEOUT_SECONDS, APPSEC_TRIVY_SCAN_TIMEOUT_SECONDS or APPSEC_SBOM_TIMEOUT_SECONDS in .env for large workloads. A timed-out scanner is removed by its unique container name; if cleanup fails, inspect that named container. No stale vulnerability database fallback is introduced. Existing strict registry order and evidence verification are unchanged.
