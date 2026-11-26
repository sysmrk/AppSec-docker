# Changelog

## V4 development — unreleased

- Disable package-removal execution, including legacy queued tasks; preserve historical evidence. Add read-only Syft/Grype lab using pinned local tool IDs and frozen Grype database.

- Plan A: package-preserving native upgrades; generic reconstruction, package removal and debloating excluded.
- Retire conflicting standalone Trivy DB updater and preserve migration history.
- Add isolated, frozen-DB native APT/debloat comparison harness with bounded Nginx HTTP smoke tests. No automatic publication or new production engine.

## v2.0.0 — 2026-11-25

- Full patch-enabled startup with deployment fingerprints and BuildKit/worker capability checks; MCP remains optional.
- Verified OS and application scan evidence, full SBOM, known-fix OS eligibility, independent patched-image rescan and unified finding comparison.
- Separate advisory recommendation and publication approval with documented risk reason; complete destination, remote manifest digest and identity verification.
- Strict ordered runtime registry sources and scoped helper mappings, explicit scanner DB preparation and bounded stage diagnostics.
- Private HTTPS Git scans with short-lived encrypted credentials and redacted findings.
- Settings navigation, idle workflow bulk export/purge, timestamped HTML/SARIF and ZIP downloads.
- Admin tool update management, cached official metadata, verified archive staging, HTTPS proxy and CA support.
- Migrations 0014–0018, independent CI image severity gate, executable maintenance scripts, revised English documentation and least-privilege MCP role guidance.
- Production gates remain: isolated execution, external SSO, multi-host affinity, immutable tool/DB evidence, tenant-aware analytics, reliable interrupted-job recovery and full infrastructure acceptance.


## v0.9.0 — 2026-11-22 — Guided UX, inventory and enterprise account foundation

- Added interactive first-run wizard and modular Control Center pages for image inventory, scan history, CVE comparison, approvals, Registry management and account security.
- Separated approved local Copa patch preparation and rescan from **second human Registry Push approval**, optional two-person separation and destination allowlist.
- Added safe diagnostic codes, remediation hints, correlation IDs and safe scan-only recovery without automatic re-Push.
- Added user disable/enable, roles, temporary password rotation, session revocation, API key rotation, failed-login lockout and optional encrypted Authenticator TOTP with one-use recovery codes.
- Added migration versions 0010–0013 and expanded GitHub Actions tests. Updated all guides; no Demo Mode, no Grafana (Metabase remains only dashboards).
- Production gates remain: isolate workers, external SSO/SCIM, multi-host staging, browser/Registry E2E, global analytics tenant restrictions, signing and DR/HA.


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
