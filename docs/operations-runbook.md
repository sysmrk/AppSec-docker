# Operations Runbook

## Start Platform

Development profile:

```bash
./scripts/harbor.sh install
./scripts/harbor.sh login
docker-compose -f docker-compose.yaml --profile platform up -d postgres buildkit minio minio-init api nginx worker scheduler grafana metabase
./scripts/setup-metabase.sh
```

Production-like split workers:

```bash
./scripts/harbor.sh install
./scripts/harbor.sh login
docker-compose -f docker-compose.yaml --profile production up -d postgres buildkit api nginx image-worker security-worker scheduler
```

## Migrations

Preferred command:

```bash
./scripts/appsecctl.sh migrate
```

Compatibility command:

```bash
./scripts/appsecctl.sh init-db
```

## Health and Metrics

```bash
curl http://127.0.0.1:8080/api/health
curl http://127.0.0.1:8080/appsec-api/health
curl http://127.0.0.1:8080/appsec-api/metrics
curl http://127.0.0.1:3001/api/health
```

## Docker Compose v1 ContainerConfig Issue

If `docker-compose` v1 fails with `KeyError: 'ContainerConfig'`, remove only the affected containers and run `up -d` again.

Example:

```bash
docker rm -f appsec_api_1 appsec_worker_1 appsec_scheduler_1
docker-compose -f docker-compose.yaml --profile platform up -d api worker scheduler
```

Do not remove named volumes unless data loss is intended.

## Production Safety Notes

- API must not mount Docker socket.
- Only workers should access Docker socket.
- Put workers on dedicated hosts when possible.
- Use a real secret manager for production secrets.
- Expose API only behind TLS and identity-aware proxy.


## Security upgrade: redact historical secrets

1. Back up PostgreSQL securely and restrict access to existing report volumes/S3/backup snapshots.
2. Run `./scripts/appsecctl.sh migrate` (migration 0006 scrubs Gitleaks raw_report and evidence/secret metadata stored in PostgreSQL).
3. Delete/regenerate reports that may contain raw credentials from pre-upgrade runs, including remote S3 objects and archival backups; **rotate exposed tokens/passwords**, because deleting reports does not revoke credentials.
4. Configure `SECURITY_ALLOWED_GIT_HOSTS`, `APPSEC_SESSION_COOKIE_SECURE=true` behind TLS and enforce report authentication.
5. Validate with `PYTHONPATH=runner python3 -m unittest discover -s tests -v`, then exercise the API with distinct users in different projects.

Limitation: Existing generated HTML/SARIF and Gitleaks JSON files are not automatically rewritten by the DB migration. Do not share old download links.
