# Production roadmap — v2

The v2 release is functional and has automated validation; it is not certified production-ready.

| Area | Delivered | Remaining acceptance work |
| --- | --- | --- |
| Execution | Full Compose platform, manual scan/patch/rescan, timeout diagnostics | Isolated Docker/BuildKit hosts, job leases/recovery, resource limits, scale and worker affinity |
| Evidence | Verified local image IDs, unified report, digest verification, SBOM | Signed provenance, immutable tool/DB snapshots, comparable DB snapshots, full E2E |
| Governance | Explicit dual decisions, advisory risk reason, source priority | External IdP/SCIM, policy versioning, signing/attestation, egress controls |
| Identity | Local RBAC, TOTP, revocation, audit | Corporate SSO, central MFA, break-glass, rate-limit/session review |
| Operations | Migrations, health, release checks and offline staging | HA, tested DR, monitoring, storage lifecycle, capacity and failure injection |
| Analytics | Metabase, optional read-only MCP | Tenant-scoped analytics and authenticated remote MCP gateway |

Release acceptance should include clean install and upgrade, authenticated private repository scan, original/patched comparison, zero-fix and unsupported-image cases, publication permission revocation, digest verification, ambiguous push reconciliation, tool update/rollback rehearsal, RBAC/MFA, history cleanup, backup/restore and large-image timeout testing. Do not treat successful CI as a substitute for deployment acceptance.
