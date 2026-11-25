# Enterprise-Facing Identity and Governance

The built-in authentication model is intended for a self-hosted tool and an incremental Enterprise upgrade. It is **not** full external identity federation yet.

## User lifecycle

Admins can use **Settings → Users & access** to inspect a user, roles, disabled/locked state, last login, password update, API key rotation, MFA status, Team memberships and recent web sessions. Actions include:
- Create account with a temporary password requiring first-login change
- Set display name or global role (`admin`, `operator`, `viewer`)
- Disable/re-enable an account; disabled accounts lose login and old API access
- Reset temporary password and revoke existing browser sessions
- Revoke all sessions without changing the password
- Rotate a machine/API key with **one-time display**; human users do not receive keys by default
- Remove Team membership (can immediately change Project access)

Server enforces protection from self-disable/self-demotion and loss of the final active Admin. Privilege changes and key events are logged through the audit subsystem. Five failed password attempts cause a 15-minute lock; admins can reset the affected password.

## MFA

Each account can opt into **TOTP authenticator MFA**, enforced for interactive login when enabled. Setup requires the current password, app enrollment and a valid code; recovery produces eight single-use codes, displayed once and stored as hashes. TOTP secrets are encrypted at rest using Fernet `APPSEC_MFA_ENCRYPTION_KEY`. Replayed TOTP steps are rejected. Enabling or disabling MFA invalidates existing web sessions.

MFA is not magic account recovery: if both authenticator and recovery codes are lost, an approved operational identity recovery process is needed. Do not delete or rotate the encryption key casually. Store it in an enterprise secrets manager and back it up securely.

The existing local authenticator is **not** OIDC, SAML, LDAP, AD or Keycloak integration. An external IdP connector, SCIM lifecycle provisioning, group-to-role mapping, MFA assurance policy, break-glass lifecycle and complete segregation of duties require separate implementation and testing.

## Teams, projects, permissions

A Team owns zero or more Projects, and users have membership roles `owner`, `maintainer`, `member`, `viewer`. Global AppSec role controls operation type while Project membership controls scope and write access. Manual unassigned workflows are visible to creator/admin; Project workflows to authorized current Team members. Only Admin/Operator with Project write rights can submit approval. No Project role or client-side hidden button substitutes for server authorization.

## Human approval / Registry governance

Manual scan starts Trivy/SBOM without an initial policy verdict. A human approves **local** Copa preparation and scanning only when verified OS fixes exist. A **separate** human publication approval requires a successful verified rescan, a post-patch advisory recommendation and a registered `allow_push` destination; not-recommended images require a documented risk reason. Setting `APPSEC_REQUIRE_SECOND_APPROVER=true` requires another authorized reviewer. Both decisions are persisted. Ambiguous Registry Push is single-attempt and must be reconciled manually.

## Metabase / MCP boundaries

Metabase is the only visualization/BI integration, with distinct logins and **global** analytics SQL. It does not inherit AppSec per-Project restrictions. Use a read-only database role, restrict access and apply TLS/SSO at the perimeter. Optional MCP is read-only and not an execution or approval integration.

## Outstanding Enterprise hardening

- Corporate OIDC/LDAP/SAML SSO, SCIM provisioning and central MFA assurance
- Worker isolation (Docker Socket) and privileged BuildKit separation
- Hardened operational recovery and rate limiting, CSRF/session review
- True multi-host prepared-image staging/affinity, HA and DR acceptance
- End-to-end Docker/Harbor/Copa/Browser tests, image digest pinning/signing, secret manager
- Per-Project Metabase/analytics segregation rather than global shared dashboards

Treat the current release as a functional upgrade requiring staging validation, not a fully certified Enterprise product.

Private repository credentials are encrypted for the specific job, expire after one hour, and are consumed once by the worker. The same MFA encryption key is required for this feature. This is separate from Registry credentials and is not an enterprise secrets vault.
