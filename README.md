# AppSec Control Center — v3 development branch

This branch starts from the stable v2.0.0 release. Development changes are not a v3 release. See [remediation research and acceptance plan](docs/v3-remediation-research.md).

## Stable baseline: AppSec Control Center v2

Self-hosted container vulnerability management and repository secret scanning, with evidence-driven image remediation and human-controlled publication. The browser is a first-class operational interface: no CI/CD system is required. CLI and REST interfaces support automation separately.

**Release 2.0.0 | Linux / WSL2 | Docker Compose | PostgreSQL | Metabase**

> Functional release, not a production certification. Run staging acceptance before sensitive deployments. Workers have Docker socket access and the patch executor uses privileged BuildKit.

## Capabilities

- Trivy scans OS and application dependencies, including unfixed findings; CycloneDX SBOM and raw scanner evidence are retained.
- Local OS-package remediation through Copa/BuildKit, only where known fixes exist. Independently scan the result and compare original and patched image identities.
- Human approval for local patch preparation, followed by a separate publication decision. The post-patch recommendation is advisory; a not-recommended result requires a documented risk reason to publish.
- Approved source priority for runtime image/tool pulls and scanner DB artifacts; controlled local output or registry publication with remote digest verification.
- One consolidated HTML report, full in-scope finding comparison, UTC timestamped downloads and ZIP export; admin-only history cleanup.
- Public/private HTTPS Git repository secret scanning with Gitleaks, separate short-lived encrypted credentials and redacted findings.
- Local identity, roles, teams/projects, account lifecycle, TOTP MFA, audit trail, optional distinct publication approvers.
- Admin-managed tool release checks and upgrades, separate from vulnerability database refresh.
- Metabase dashboards and optional read-only MCP analytics. No demo data and no Grafana.

## Install

Use a trusted isolated Linux/WSL2 host with Python 3.10+, Git, Docker Engine and Docker Compose v2 or compatible later version, enough disk space, and access to approved images/package repositories. Local HTTP ports 8080, 3001 and 9000/9001 must be available.

```bash
git clone https://github.com/sysmrk/AppSec-docker.git
cd AppSec-docker
./appsec wizard
```

Or run:

```bash
./appsec setup
./appsec start
./appsec doctor
./appsec credentials
```

Setup generates credentials and the MFA encryption key without overwriting an existing .env. Startup always launches the full patch-enabled platform, applies migrations, verifies the deployed revision and BuildKit runtime, and provisions analytics. The old --patching switch remains compatible. A successful start does not prove every remote source is reachable.

Open **http://127.0.0.1:8080** (initial user admin). Metabase: **http://127.0.0.1:3001**, separate login. Never expose local HTTP directly; configure TLS and Secure cookies for nonlocal use. MCP is off unless separately enabled.

## First workflow

1. In Settings → Registries configure approved pull sources and any allowed publication destination; provision worker registry credentials separately.
2. Open Image scan, enter a real image reference and optionally a Project. Check readiness; actual pull/auth is verified only during execution.
3. Review the original scan and SBOM in My workflows. No automatic patch or push.
4. If known OS fixes exist, approve Prepare patch & rescan. The local image must differ and the second scan must verify its identity.
5. Review the comparison and recommendation. Keep the local result or approve a complete allowed registry destination. Provide a risk reason if not recommended. Optional second-person approval is supported.
6. Export the HTML report; publication records the destination, digest and timestamp after verification.

For private Git scanning use Repository scan and a scoped read-only PAT/password in the separate credential fields. The platform does not repair application dependency code or leaked credentials automatically.

## Navigation

| Workspace | Purpose |
| --- | --- |
| Overview | Latest ten image workflows and recent repository jobs |
| Image scan | Guided image intake |
| Repository scan | Redacted secret findings |
| My workflows | Paginated history, decisions, export and admin deletion |
| Images & scans | Search scanned images, history and comparison |
| Approvals | Pending human decisions |
| Settings | Tool updates, Registries, Users & access, Projects & policies, System health, Integrations, My profile & MFA |

Reports open from a selected workflow or scan rather than an empty Results menu. Admin categories are role-restricted.

## Operations

```bash
git fetch origin main --tags
git merge --ff-only origin/main &&
  ./appsec start &&
  ./appsec doctor
```

Back up data and drain active jobs before upgrading. Preserve .env, docker-compose.override.yaml and named volumes. Use the tested release tag for a reproducible source checkout; scanner image tags and external feeds still require separate pinning.

| Command | Purpose |
| --- | --- |
| ./appsec status | Compose status |
| ./appsec logs worker | Worker diagnostics |
| ./appsec stop | Stop, preserve volumes |
| make mcp-up / make mcp-down | Optional read-only MCP |
| ./scripts/appsecctl.sh ci image IMAGE | Explicit CI severity gate, no automatic push |
| ./scripts/appsecctl.sh ci security secrets HTTPS_REPO | Explicit secret-scan CI gate |

## Documentation

| Guide | Scope |
| --- | --- |
| [Architecture](docs/architecture.md) | Services and trust boundaries |
| [Operations](docs/operations-runbook.md) | Install, upgrade, diagnostics, backup |
| [User guide](docs/user-guide.md) | Browser operations |
| [Workflow](docs/workflow.md) | State, evidence and approvals |
| [Reports](docs/consolidated-report.md) | Interpretation and naming |
| [Registry](docs/registry.md) / [Source priority](docs/image-source-priority.md) | Pull, remediation and publication |
| [History & cleanup](docs/history-and-cleanup.md) | Export and deletion boundaries |
| [Tool updates](docs/tool-updates.md) | Upgrade manager and offline transfer |
| [Identity](docs/enterprise-features.md) / [Inventory](docs/image-inventory.md) | Access and history |
| [API](docs/api-guide.md) / [CI](docs/ci-policy-guide.md) | Automation |
| [Database](docs/database.md) | Schema and migration |
| [Metabase](docs/metabase.md) / [MCP](docs/mcp.md) | Analytics |
| [Security review](docs/security-review.md) / [Roadmap](docs/production-roadmap.md) | Residual risks and release gates |

See [CHANGELOG](CHANGELOG.md). Main commits receive change-<SHA> tags; VERSION defines the semantic tag. The v2 label does not imply that external identity federation, isolated multi-host execution, high availability, or full end-to-end acceptance are complete.

**v3 development:** see [planning and local AI](docs/v3-remediation-planning.md) and [isolated candidate lab](docs/v3-remediation-lab.md). Experimental OS/library candidates and dependency checks are not exposed to production workflows. Go migration is deferred.
