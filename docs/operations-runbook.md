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
