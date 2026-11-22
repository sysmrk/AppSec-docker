# AppSec-docker static security review (2026-11-22)

Scope: default branch code, Compose config, API, DB, secret scanning, CI and MCP design. Static review only: no Docker runtime or live Postgres/Harbor/BuildKit tests performed.

## Changes in this hardening branch

| Severity | Finding | Remediation | Verification |
| --- | --- | --- | --- |
| Critical | Gitleaks match/secret/line stored in raw JSON, DB and findings | Request scanner redaction, strip sensitive fields again before saving, hide legacy raw fields in API, irreversible Alembic cleanup | Unit tests + migrate; old disk/S3/backups need manual removal |
| High | Reports downloadable with UUID by default | Force authenticated downloads and per-resource project checks | Negative API tests required |
| High | Project-sensitive jobs and findings retrievable by arbitrary authenticated user | Enforce project membership for scoped detail/report/write/download endpoints; filter lists in SQL | Multi-tenant integration tests still required |
| High | Arbitrary git clone target enables network reach to internal hosts | HTTPS and exact hostname allowlist; no embedded credentials or raw IP URLs | Unit tests; enforce DNS/egress ACLs too |
| Medium | Session cookie sent without Secure | Set configurable Secure cookie, default true | Browser HTTPS validation |
| Medium | Risk acceptance expiry optional | Enforce future timezone-aware expiry | API validation |
| High | API/worker image privileges and Docker socket | API remains socket-free, workers still need dedicated isolation | Open item |
| High | Privileged BuildKit, unpinned scanner images, network access, static default credentials | Operational guardrails; pin digests/rotate secrets before production | Open item |
| Medium | No meaningful runtime integration tests | Add unit tests; Docker Compose validation exists | Open item |

## Residual risk and production gates

- Worker socket gives broad access to host. Use isolated build hosts or remote BuildKit with restricted credentials; never co-locate with sensitive production workloads.
- Review and pin release digests for Trivy, Gitleaks and BuildKit; validate patches in a staging registry before promotion.
- Do not expose HTTP MCP directly to Internet: it is read-only but has organizational vulnerability data. Place it behind HTTPS, identity-aware OAuth proxy and least-privilege Postgres role.
- DB cleanup does **not** scrub old report files, S3 objects or backups. Rotate secrets and purge/expire those copies under retention policy.
- Existing global jobs remain shared across authenticated users; assign a Project for tenant isolation.
- RBAC, CSRF, brute-force throttling, email/webhook SSRF, disaster recovery, vulnerability DB freshness and image signature verification require dedicated end-to-end review.
- Tests here are source/logic-only; actual scan, Copa patch, registry push and database migration must be validated in an isolated test deployment before production sign-off.

## Review checklist

```bash
docker compose -f docker-compose.yaml config
PYTHONPATH=runner python3 -m unittest discover -s tests -v
./scripts/appsecctl.sh migrate
docker compose --profile platform up -d postgres api nginx
# Verify unknown user -> 401; cross-project user -> 403; approved user -> success.
```


## Optional MCP review

The new `integrations/mcp/` service has no Docker socket, report volumes or write tools, uses a read-only PostgreSQL transaction, and has an opt-in Compose profile. It still exposes cross-project aggregates to whoever can connect: do not add it to shared networks or expose publicly without OAuth/TLS and a least-privilege DB account. `docs/mcp.md` provides deployment and AI client instructions. Unit tests verify SQL transaction read-only configuration, input caps and UUID validation.


Additional follow-up: unscoped dashboard/history/teams/audit logs are admin-only; a source scan now cleans up the cloned workspace and Git no longer follows cross-host redirects. The `ci security` command is fail-closed when the scanner returns a non-success status. Legacy `DOWNLOADS_REQUIRE_AUTH=false` is ignored intentionally; authentication is always required.


Scanner failure handling: Gitleaks uses an explicit detection exit code (17). Only 0 (no leaks) and 17 (leaks found) count as an executed scan; all other exit codes fail the job. The script also removes the temporary cloned repository in a finally block. `make down` now includes the optional MCP profile when shutting down the full stack.
