# Security review and release acceptance — v2

Scope: tracked source, deployment configuration, operational scripts, API contracts, workflow and documentation. Static review and repository CI evidence; not a penetration test or production certification.

| Control | Implemented | Residual exposure / required acceptance |
| --- | --- | --- |
| Image identity | Validate original and patched Docker IDs and independent rescan; pull published manifest by digest | Mutable tags and different DB snapshots; signatures/provenance not enforced |
| Remediation scope | Only known OS fixes; no automatic application-dependency remediation | Unsupported OS and incomplete coverage fail visibly; validate supported base images |
| Authorization | Role/Project checks, explicit human decisions, optional distinct publication reviewer, risk reason | Legacy unassigned data, full tenant/authorization and race testing |
| Execution | API socket-free; worker and scheduler own execution; stage timeouts | Docker socket and privileged BuildKit are high trust; separate hosts, leases and recovery needed |
| Registry | Ordered approved pull sources; helper LLB mapping and deny policy; publication recheck | Not a firewall; package egress, auth realms, redirects, daemon configuration and tag immutability remain independent |
| Secrets | Gitleaks redaction, HTTPS Git host restrictions, expiring encrypted credentials | Historical disk/S3/backups, DNS/egress controls, private Git acceptance |
| Identity | PBKDF2, hashed sessions/keys, local lifecycle, TOTP encryption/replay prevention, recovery codes | No corporate SSO/SCIM; verify CSRF, rate limits, secrets manager and recovery |
| Artifacts | Authenticated per-resource downloads, bounded export and admin cleanup | Presigned URL scope/expiry, backup retention, object versioning, partial deletion |
| Updates | Admin approval, SHA256 archive check, stable tag/version verification, TLS | Not independent signatures; tag pinning, compatibility and rollback rehearsal |
| Analytics | Metabase and optional read-only MCP | Global scope, separate authorization; restrict SQL columns/roles and remote gateway |
| CI | Explicit image threshold gate independent of manual advisory; secret gate fails closed | Full real scanner/registry/browser E2E remains required |

## Acceptance checklist

- Verify clean install and migration on a copy of existing data; check deployed revision and full patch runtime.
- Exercise cross-project access and direct report/artifact IDs with Admin, Operator and Viewer accounts.
- Verify MFA recovery, temporary password enforcement, key revocation, CSRF and HTTPS cookies.
- Test successful, failed, no-fix and unsupported image scans; verify actual post-patch image and digest.
- Test source fallback, all-disabled fail-closed mode, permission revocation before publication, and uncertain push handling.
- Test public and private repository scans, credential expiry and absence of raw secrets in reports/logs.
- Validate release transport, checksum rejection, prior active version retention and timeout cleanup.
- Validate history purge, restore, retention and independent Metabase/MCP authorization.

CI covers Python/JS/Compose, automated tests, PostgreSQL migrations/SQL, selected real BuildKit source-policy and repository-scanner smoke tests and MCP STDIO handshake. It does not establish production security, all supported image families, remote OAuth, multi-host affinity or disaster recovery. Do not claim production signoff from CI alone.
