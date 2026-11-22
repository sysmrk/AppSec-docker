# AppSec Control Center — User Guide

No demonstration data, no CI/CD requirement. Every operation and finding in this guide uses the **real system**.

## First login

On your Docker/WSL host:

```bash
./appsec setup
./appsec start
./appsec doctor
./appsec credentials
```

Open `http://127.0.0.1:8080`; sign in as `admin` with the generated password. The default URL works from the same host. For a different computer, use an authenticated HTTPS proxy or SSH tunnel, not direct insecure public exposure.

## Menu overview

| Menu | Intended user | Action |
| --- | --- | --- |
| Overview | Everyone | View real jobs, severity counts and last results |
| New manual scan | Operator/Admin | Register an image, start a human-guided workflow |
| My workflows | Members and creator | Monitor scan stages, review, approve or finish |
| Scan repository | Operator/Admin | Scan an approved HTTPS Git repository using Gitleaks |
| Results | Everyone with access | CVE table, policy result, patch diff, authenticated downloads |
| Administration | Admin | Create users/teams/projects, assign team roles, set policy thresholds |
| System health | Admin | Worker/Scheduler heartbeats, queue status and database health |
| Integrations | Everyone | Metabase analytics and optional MCP setup |

## Scan an image without CI/CD

Click **New manual scan**. Supply a real image reference (for example, `registry.example.com/team/api:1.4.0`). The image must be available to the Docker daemon and registry credentials used by the Worker. This form does not upload Docker tar archives. Choose an existing Project or leave it unassigned (visible to its creator/admin).

Click **Start guided scan**. The scan is **asynchronous**, and the web interface shows the actual steps:

```text
Queued → Trivy scan → SBOM → Security policy → Awaiting operator decision
```

In **My workflows**, select your workflow to open progress, counts and reports. Refresh while a worker is busy. If no record exists, the system correctly shows an empty list, not fake results.

## Inspect and approve

After the first scan job finishes successfully, the UI displays an **Awaiting approval** state. Inspect:
- Critical/High/Medium/Low counts and CVE list
- Policy decision and any violations
- Original SBOM and available authenticated HTML report
- Whether patching is enabled on the actual server
- Proposed registry destination before writing anything

Choose either:

**Finish without patching.** Stores your decision; keeps the original scan, SBOM and report.

**Approve patch + registry push.** Only appears when the admin started the server with `./appsec start --patching`. You must check the registry-write acknowledgment and accept a second confirmation prompt. This creates a **single-attempt** continuation job. Copa patches the original scan's image, pushes a new tag, rescans it, compares fixed/remaining/introduced CVEs, reruns the policy and stores final reports.

A failed stage appears as failed, not passed. Job/patch retries can be unsafe after a registry write; automatic retries are disabled for approved continuation jobs.

## Repository secret scanning

In **Scan repository**, enter an HTTPS repository URL. The hostname must be in `SECURITY_ALLOWED_GIT_HOSTS`. Gitleaks stores redacted findings; raw secret values should never be copied into the UI. Legacy files created before hardening still require deletion and credential rotation.

## Administration

An Admin can create a Team, create a Project owned by that Team, add users and assign team roles. Use these Project IDs when starting scans to apply authorization. The UI provides policy inputs for max Critical/High/Medium/Low vulnerabilities.

The user creation form generates a random API key and shows it **once**; securely store it if CI/CD/API access is needed. Provide user passwords via your approved secure channel and rotate initial passwords.

Project-scoped data is visible to authorized team members; manual workflow decisions additionally require an Operator/Admin role with Project write access. Global/unassigned manual runs are restricted to creator and administrators. Metabase uses its own administrator login and is a global analytics view, **not** per-Project RBAC.

## Analytics

Metabase: `http://127.0.0.1:3001` — login details via `./appsec credentials`.

Three dashboards are provisioned automatically:
- **AppSec Security Overview** (scan status, vulnerabilities, policy gates, reports)
- **AppSec Manual Operations** (workflows, pending approvals, decisions, queue and patch results)
- **AppSec Vulnerability Trends** (severity trends, top CVEs and failed policies)

Metabase is for observing and filtering data. **Approvals happen in Control Center**, never by editing SQL or clicking Metabase cards.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Login fails | `./appsec credentials`, account and HTTPS cookie settings |
| Image scan queued too long | `./appsec doctor`, `./appsec logs worker`, Docker access |
| No vulnerabilities | Real scan success, Trivy DB freshness, registry image available |
| Awaiting approval but Patch unavailable | Admin must explicitly enable `--patching` and configure registry |
| Download returns 401/403 | Valid AppSec session/API key and Project permission |
| Metabase unavailable | `./appsec doctor`, `./appsec logs metabase`, dashboard bootstrap |
| CVE table incomplete | UI caps each request to 200 rows; export full report for exhaustive data |
| MCP not running | Normal; it is **opt-in** and not necessary for the UI |
