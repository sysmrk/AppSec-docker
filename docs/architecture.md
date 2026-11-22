# AppSec Architecture

```text
Users + browser                           CI / API or authorized MCP AI
       |                                            |
Nginx (local 8080)                     Optional read-only MCP (separate)
       |
FastAPI + session/RBAC + first-party UI
       |
PostgreSQL: Users, Teams, Projects, Workflows, Scan Jobs, Approvals, Results
       |
Worker (high-trust Docker Socket)
       |
Trivy original -> SBOM -> Policy -> Review (human decision)
       |
Optional approved local Copa + privileged BuildKit
       |
Trivy patched -> SBOM -> CVE diff -> final Policy
       |
Human Registry publication approval (+ optional second approver)
       |
Approved Registry destination -> single-attempt Docker push
       |
Persisted status and authenticated reports
       |
Metabase: aggregated real SQL dashboards (separate login, read-only recommended)
```

## Domain boundaries

- **Human UI:** static HTML/CSS/JS served through FastAPI at local `/ui`. `app.js` handles core scan flow, `workspace.js` handles inventory, approvals, Registry and identity. No external JS CDN or fake data.
- **API:** FastAPI enforces roles, Project membership, human approval, new-user password rotation and optional MFA login. Cookie browser writes require a same-origin custom header; server errors include request IDs and safe repair hints.
- **Core:** PostgreSQL is the source of truth for jobs, scan results, approvals, audit and image inventory. Workers claim queued jobs and use explicit `scan`, `continue_patch`, `publish_patch` modes. Legacy advanced automated `patch` remains privileged and separately opt-in.
- **Image inventory:** read-only, scoped SQL queries; scan history and CVE difference, not direct registry crawling.
- **Registry metadata:** HTTPS hostname, Project scope, allow_push flag; no Registry secrets, passwords or arbitrary URL probes stored.
- **Identity:** local users, Team membership, lifecycle, API-key rotation, audit, lockout, encrypted TOTP MFA and recovery codes. Corporate OIDC/SAML/LDAP is not yet implemented.
- **Analytics:** Metabase only, with Security Overview, Manual Operations and Vulnerability Trends dashboards; account and data authorization are **independent** of AppSec's Project RBAC.
- **AI:** optional read-only MCP, not an approval/execution path.

## Scale and safety limitations

The current Worker needs Docker Socket access even for scanning; patching additionally relies on privileged BuildKit. Separate hosts, restricted service accounts and network isolation are required before sensitive Enterprise deployments. **Local prepared patch images are not portable between Docker hosts**. A horizontally scaled workflow requires fixed Worker affinity or an approved staging registry promotion model; these are not yet solved by the UI.

MFA encryption key is configured using `APPSEC_MFA_ENCRYPTION_KEY`. Recovery codes are hashes; one-time TOTP secrets are Fernet-encrypted. Back up the encryption key for recoverability. Current Metabase and MCP SQL access is global; a SELECT-only DB user and trusted network are required for production.
