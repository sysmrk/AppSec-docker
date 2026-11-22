# Changelog

## v0.6.0 — 2026-11-22 — Manual workflows and Metabase consolidation

- Development changes committed directly on `main`, each automatically tagged `change-<SHA>`; semantic release tags follow the `VERSION` file.
- Removed Grafana; Metabase is the sole analytics service. Three provisioned dashboards cover image vulnerabilities, manual workflow reviews and CVE trends.
- Introduced interactive non-CI/CD scan/approval UI, persisted approval decisions, one-attempt Copa Patch/Push continuation, rescan and policy/report results.
- Added user/team/project/membership/policy administration, worker health, PostgreSQL migration/tests and optional read-only MCP. No Demo Mode.
- Still requires production readiness work for Docker Socket/BuildKit isolation, SSO/MFA, CSRF, least-privilege analytics, signing and real infrastructure E2E testing.


## Unreleased — 2026-11-22 security hardening and optional MCP

- Add opt-in, read-only MCP adapter in an isolated Compose profile, local HTTP/STDIO transports, AI client / Inspector documentation and unit tests.
- Redact Gitleaks Match/Secret/Line before persistence, remove secret evidence, clean cloned workspaces, add irreversible DB cleanup migration for historical credentials (old files/S3/backups still need rotation/purge).
- Enforce authenticated report/artifact downloads and project-scoped access; restrict global administrative aggregations.
- Constrain Git clone to approved HTTPS hosts without redirects/embedded credentials.
- Require future expiry for accepted risks and HTTPS Secure session cookies.
- Fix CI secret scanning fail-open status handling; use Docker Compose v2 scripts and preflight.
- CI now validates Compose/Python and runs unit tests; not a substitute for integration testing.

## v0.1.0 - 2026-06-18

- Added Docker Compose based AppSec image scanning and Copa patching pipeline.
- Added PostgreSQL persistence for scans, vulnerabilities, patches, diffs, policy results and reports.
- Added Grafana and Metabase dashboards.
- Added MinIO/S3-backed HTML reports with image metadata, CVSS details and Copa reduction summary.
- Added Harbor support, BuildKit, scheduler, workers, API, policy gates and CI documentation.
- Added operational scripts for preflight, Trivy DB update, Metabase provisioning and clean shutdown.
