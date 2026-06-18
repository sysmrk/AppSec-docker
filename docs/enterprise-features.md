# Enterprise Features

## Teams and Projects

Create a team:

```bash
curl -X POST http://127.0.0.1:8080/appsec-api/api/teams \
  -H 'X-API-Key: appsec-dev-key' \
  -H 'Content-Type: application/json' \
  -d '{"name":"Platform Security"}'
```

Create a project:

```bash
curl -X POST http://127.0.0.1:8080/appsec-api/api/projects \
  -H 'X-API-Key: appsec-dev-key' \
  -H 'Content-Type: application/json' \
  -d '{"name":"Core AppSec","slug":"core-appsec","team_id":"<team-id>"}'
```

Queue a job for a project:

```bash
curl -X POST http://127.0.0.1:8080/appsec-api/api/security-jobs \
  -H 'X-API-Key: appsec-dev-key' \
  -H 'Content-Type: application/json' \
  -d '{"kind":"secrets","target":"https://github.com/example/repo.git","project_id":"<project-id>"}'
```

## Database Policies

Create a global or project policy. If `project_id` is omitted, the policy is global.

```bash
curl -X POST http://127.0.0.1:8080/appsec-api/api/policies \
  -H 'X-API-Key: appsec-dev-key' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Strict Image Policy",
    "project_id": "<project-id>",
    "rules": {
      "max_critical": 0,
      "max_high": 0,
      "max_medium": 5,
      "max_low": 999999
    }
  }'
```

Project policies override global policies for project-linked image pipelines.

## MinIO Artifact Storage

Start MinIO:

```bash
docker-compose -f docker-compose.yaml --profile storage up -d minio minio-init
```

Enable S3 artifact storage:

```env
ARTIFACT_STORAGE=s3
S3_ENDPOINT_URL=http://minio:9000
S3_BUCKET=appsec-artifacts
S3_ACCESS_KEY_ID=appsec-minio
S3_SECRET_ACCESS_KEY=appsec-minio-secret
```

Generated reports are still created locally first, then uploaded to S3-compatible storage. The database stores the final `s3://...` path.

## Secret File Support

Production deployments should use file-mounted secrets when possible:

```env
POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password
APPSEC_ADMIN_API_KEY_FILE=/run/secrets/appsec_admin_api_key
S3_ACCESS_KEY_ID_FILE=/run/secrets/s3_access_key_id
S3_SECRET_ACCESS_KEY_FILE=/run/secrets/s3_secret_access_key
```

This keeps secret values out of plain environment variables.
