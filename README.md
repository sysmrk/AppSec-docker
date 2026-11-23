# AppSec Control Center

AppSec is a self-hosted, human-first application for **real** container and repository security operations. You do **not** need GitLab/Jenkins or a CI/CD pipeline to scan an image, inspect CVEs, build a locally patched image, and approve a Registry push. A separate CLI and API remain available for automation.

**No demo mode or artificial scan data.** Reports come from Trivy, Gitleaks, Policy and the AppSec PostgreSQL database. Metabase is the **only analytics product**; Grafana was removed. An optional **read-only** MCP integration can expose analytics to an authorized AI client.

> **Engineering status:** Release candidate for a larger product workflow, **not yet certified production-ready**. Unit tests, PostgreSQL migrations and SQL analytics run in GitHub Actions. Full Docker/Trivy/Copa/Harbor browser acceptance, isolated workers, and external SSO/OIDC are still open production gates.

## First installation

Requires Linux/WSL2, Docker Engine/Desktop with Docker Compose **v2**, Python 3.10+, Git and access to approved registry images/Trivy vulnerability databases.

```bash
git clone https://github.com/sysmrk/AppSec-docker.git
cd AppSec-docker
./appsec wizard
```

The interactive wizard validates Docker, generates random local credentials and an MFA encryption key in `.env` (without overwriting existing configuration), explains what will start, and runs the **scan-only** platform after confirmation. For manual operations instead:

```bash
./appsec setup
./appsec start
./appsec doctor
./appsec credentials
```

AppSec UI: **http://127.0.0.1:8080**. Metabase Analytics: **http://127.0.0.1:3001** (own login). The initial AppSec username is `admin`. See generated initial credentials with `./appsec credentials` only on a trusted terminal.

## Human-guided image workflow

1. **New manual scan**: supply an actual image reference such as `harbor.example.org/team/api:1.4.0`; choose an optional Project. The form accepts registry references, **not a TAR upload**.
2. **Check readiness**: see actual Worker heartbeat and registered Registry metadata, clearly distinguishing unverified image pull.
3. **Scan**: Trivy finds CVEs, creates CycloneDX SBOM, applies Policy and stores reports without patching or pushing.
4. **Review**: use **My workflows** or **Approvals** to read severity counts, package fixes, scan details and reports.
5. **Prepare patch** (optional): after explicit approval, Copa/BuildKit creates a **local** patched image. Trivy rescans it, compares fixed/remaining/introduced CVEs and evaluates the final Policy. **Nothing has been pushed.**
6. **Approve publication** (separately): a valid, policy-passed prepared image can be published only after a second explicit confirmation and an Admin-approved Registry destination. Production can require **two distinct approvers** using `APPSEC_REQUIRE_SECOND_APPROVER=true`. Or choose **Finish without publishing**.
7. **Publish and report**: an authorized Worker publishes with a single-attempt job. Ambiguous Registry errors are never automatically retried. Errors include stable codes and plain-language troubleshooting hints.

Patch preparation and publication require opt-in privileged BuildKit: `./appsec start --patching`, approved Registry credentials available to the Worker, and Registry metadata marked `allow_push`. Default installation remains scan-only.

Trivy stores its vulnerability and Java databases in `trivy-cache/` at the project root. Set `TRIVY_CACHE_PATH` to an absolute host path to use a different directory. When upgrading an installation with an existing `appsec_trivy_cache` Docker volume, copy its contents into the host cache before restarting the scanner to retain downloaded databases.

In **Administration → Security policy**, select a project or the global default and save severity limits. **Report only** keeps the findings and disables threshold enforcement for scans using that policy. Registry publication requires an enforced policy pass after patching.

## Main navigation

| Screen | Purpose |
| --- | --- |
| Overview | Live queue, recent scans and security findings |
| New manual scan | Guided, non-CI/CD image scanning with readiness check |
| My workflows | Scan stages, CVEs, safe decisions, patch and publication status |
| Images & scans | Image inventory, history, search, two-scan CVE comparison |
| Approvals | Authorized pending manual decisions |
| Scan repository | HTTPS Git repository Gitleaks scan and redacted findings |
| Results | CVE details, policy, SBOM, patch diff and report downloads |
| Users & access (admin) | User lifecycle, roles, sessions, password reset, API key rotation |
| Registries (admin) | HTTPS Registry metadata and explicit push authorization |
| Administration (admin) | Teams, Projects, policies and new human account creation |
| My profile | Password changes, encrypted authenticator MFA, recovery codes |
| System health (admin) | Real Worker/Scheduler heartbeats and queues |
| Integrations | Metabase, optional read-only MCP |

## User and enterprise safety

The built-in identity model supports `admin`, `operator`, `viewer`, Project/Team membership, disabling accounts, safe last-admin protection, session revocation, API key rotation, login lockout and mandatory first-login password change for new users. Human API keys are **not issued by default**.

Optional authenticator MFA supports encrypted TOTP secrets, replay prevention and one-time recovery codes. `./appsec setup` generates the encryption key for a fresh installation; back up that key securely before production. MFA enrollment and account actions are audited. It is **not** equivalent to corporate OIDC/LDAP/SAML SSO.

All data-changing cookie-session requests require a first-party browser header. Report downloads require valid identity and access. The Worker still has Docker Socket privileges for scanners; **production isolation remains essential**. Metabase has independent authentication and globally scoped analytics, so restrict its users and use SELECT-only DB credentials in production.

## Commands

| Command | Description |
| --- | --- |
| `./appsec wizard` | Guided first run (starts scan-only after confirmation) |
| `./appsec setup` | Generate secure `.env`, never overwrite existing config |
| `./appsec start` | Start standard platform, migrate DB, provision Metabase |
| `./appsec start --patching` | Enable optional privileged patch executor |
| `./appsec doctor` | Check Docker, API/DB, workers, Metabase and configuration |
| `./appsec status` / `./appsec logs worker` | Inspect actual execution health |
| `./appsec stop` | Stop containers, preserve named volumes |
| `make mcp-up` / `make mcp-down` | Opt-in read-only AI adapter |
| `./scripts/appsecctl.sh ci image IMAGE` | Scan-only CI security gate |

## Documentation

- [Human User Guide](docs/user-guide.md)
- [Workflow State and Approval Guide](docs/workflow.md)
- [Installation & Operations Runbook](docs/operations-runbook.md)
- [Registry & Publication](docs/registry.md)
- [User Identity & Enterprise Controls](docs/enterprise-features.md)
- [Image Inventory & Diagnostics](docs/image-inventory.md)
- [Metabase Analytics](docs/metabase.md)
- [API Guide](docs/api-guide.md)
- [Database & Migrations](docs/database.md)
- [Architecture](docs/architecture.md)
- [CI Security Gate](docs/ci-policy-guide.md)
- [Optional MCP / AI](docs/mcp.md)
- [Security Review](docs/security-review.md) / [Production Roadmap](docs/production-roadmap.md)

**Versioning:** changes are committed directly to `main` and annotated `change-<SHA>` tags are created automatically by GitHub Actions. The `VERSION` file controls semantic version tags. Always inspect CI and test in staging before deploying to a sensitive environment.
