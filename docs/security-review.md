# AppSec-docker static security review (2026-11-22)

Scope: default branch code, Compose config, API, DB, secret scanning, CI and MCP design. Static review only: no Docker runtime or live Postgres/Harbor/BuildKit tests performed.

## Implemented changes on main

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
- CI applies migrations to actual PostgreSQL and validates Metabase card SQL with EXPLAIN. Full image scan, Copa patch, registry push, browser interaction and upgrade against production datasets still require staging verification.

## Review checklist

```bash
docker compose -f docker-compose.yaml config
PYTHONPATH=runner python3 -m unittest discover -s tests -v
./scripts/appsecctl.sh migrate
docker compose --profile platform up -d postgres api nginx
# Verify unknown user -> 401; cross-project user -> 403; approved user -> success.
```


## Optional MCP review

The new `integrations/mcp/` service has no Docker socket, report volumes or write tools, uses a read-only PostgreSQL transaction, and has an opt-in Compose profile. It still exposes cross-project aggregates to whoever can connect: do not expose it outside the trusted Docker network or publicly without OAuth/TLS and a least-privilege DB account. `docs/mcp.md` provides deployment and AI client instructions. Unit tests verify SQL transaction read-only configuration, input caps and UUID validation.


Additional follow-up: unscoped dashboard/history/teams/audit logs are admin-only; a source scan now cleans up the cloned workspace and Git no longer follows cross-host redirects. The `ci security` command is fail-closed when the scanner returns a non-success status. Legacy `DOWNLOADS_REQUIRE_AUTH=false` is ignored intentionally; authentication is always required.


Scanner failure handling: Gitleaks uses an explicit detection exit code (17). Only 0 (no leaks) and 17 (leaks found) count as an executed scan; all other exit codes fail the job. The script also removes the temporary cloned repository in a finally block. `make down` now includes the optional MCP profile when shutting down the full stack.

The CI test suite includes a real MCP STDIO tools/list handshake (no Postgres required). It verifies the expected read-only tool catalogue is discoverable by an official MCP client. HTTP transport, live SQL data, auth gateway and production scanning still require runtime tests.


System Health records DB heartbeats (migration 0008), not OS or Docker Socket access. Worker heartbeats can be stale while a scan is busy. The UI avoids declaring a worker down based solely on this information. Operational monitoring and alerting remain separate production concerns.


## Manual UI and sole Metabase analytics (2026-11-22)

Grafana has been removed from Compose, Nginx and tracked provisioning. Its old named Docker volume is intentionally preserved to avoid data loss. Metabase is the only dashboard system, with Security Overview, Manual Operations and Vulnerability Trends dashboards. The cards are SQL-checked in CI, but Metabase's independent authentication and global database visibility require a restricted account and ideally a SELECT-only database role for production.

Manual workflows persist a scan-only job, user/Project identity, human finish or approve-patch decision, approving user/time and optional **single-attempt** patch/push continuation. Original scan and policy status must be completed before approval. Backend requires role/Project write authorization, explicit confirmation and active patch setting; Worker also checks the feature flag. Project access is rechecked against current team membership, and unassigned manual runs are private to creator/admin.

**Remaining production risks:** scanning Worker Docker Socket privilege, privileged BuildKit isolation, missing OIDC/MFA/CSRF hardening, cross-Project analytics access, image signing and digest pinning, full real Docker/Harbor/Copa/browser E2E tests and backup/restore validation. No demos or fake findings are created.
