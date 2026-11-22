# User Guide — Working with AppSec without CI/CD

The Control Center uses **real PostgreSQL and scanner results**. An empty screen means no matching operation exists; there is no demo mode.

## Login and initial password

Start via `./appsec wizard` or `./appsec setup && ./appsec start`. Open **http://127.0.0.1:8080** on the local host and sign in with the generated admin credentials (`./appsec credentials`). New human accounts created in the UI require an initial password change before other operations become available.

If an authenticator MFA code is required, the login form reveals a field for a six-digit code or a one-time recovery code. Failed password attempts can temporarily lock the account; ask an admin to reset it if necessary.

## New manual scan

Enter a real image reference. Use **Check readiness** before starting. This checks image name syntax, registered Registry metadata and actual Worker heartbeat, **not** image existence or successful login to the Registry. The first real Trivy attempt verifies pull availability.

Select a Project if required. AppSec queues a scan-only job. Under **My workflows** you can inspect Trivy results, CycloneDX SBOM and the security Policy. Failures show a stable error code, plain-language title and corrective hint. Copy the request/job ID when contacting an administrator.

## Separate local Patch and final Registry publication

After the original scan completes:
- **Finish without patch** keeps the scan and reports only.
- **Prepare patch & rescan** builds a **local** patched image with Copa/BuildKit. Nothing is pushed. It requires an explicit checkbox and a configured privileged executor.
- After Trivy rescans the patched image, inspect the fixed/remaining/introduced CVEs and final Policy.
- **Finish without publishing** keeps the local result (subject to worker image retention).
- **Approve Registry Push** is a **second** distinct consent. Only a policy-passed image going to an explicitly registered `allow_push` destination can be published. Production can require a second authorized operator.

Failed or uncertain pushes are **not retried automatically**. They need an operator to verify the destination first. Failed initial scans can be restarted safely as a **new scan-only workflow**, retaining history.

## Images & scans

Search by image name, tag/digest or repository. Each image shows its actual scan history, severity counts and dates. Compare any two accessible scans to see fixed, still-present and introduced CVEs. Every result and download requires correct Project access; the UI displays at most a bounded number of CVEs and report exports are better for complete data.

## Approvals

**Approvals** shows only actual scans awaiting authorized review or publication. **My workflows** retains history and in-progress work. Review the scan, choose the appropriate action and record the decision. Do not use Metabase to approve changes.

## Repository scan

**Scan repository** accepts allowed HTTPS Git targets and uses Gitleaks. Secrets are redacted before normal persistence and UI display. Historic pre-hardening files may still need cleanup and credential rotation.

## Administration and Users & access

Admins can create Teams, Projects, severity policies and human users. New users have a temporary password requiring change at first login; API keys are **not issued automatically**.

In **Users & access**, an admin can inspect a user, role, state, MFA status, last login, Team membership and recent sessions; change the global role, disable/reenable a user, revoke sessions, reset password or rotate the API key. Keys are displayed **once** after rotation. Role changes and disabled accounts trigger session revocation. Disabling also invalidates the legacy API key. Self-demotion and disabling the final active admin are prohibited.

## My profile: authenticator MFA

Change your password with your current password; old sessions are revoked and you sign in again. To enable MFA:
1. Enter your current password under **Set up authenticator MFA**.
2. Enter the secret into a compatible authenticator application.
3. Confirm the generated six-digit code within ten minutes.
4. Save the eight one-time recovery codes offline; they are displayed once. Web sessions are revoked so you must sign in again.

Disabling MFA requires your password plus a fresh authenticator or unused recovery code and revokes sessions. Encryption key rotation is an operator maintenance action: keep `APPSEC_MFA_ENCRYPTION_KEY` available for database recovery. Built-in TOTP does **not** add OIDC/AD/LDAP SSO.

## Diagnostics and help

| User-facing code | Common cause | Recommended action |
| --- | --- | --- |
| `REGISTRY_AUTH` | Wrong registry credentials | Ask admin to check worker Registry login and namespace privileges |
| `REGISTRY_NOT_FOUND` | Wrong tag/digest or repository | Check exact image reference |
| `REGISTRY_NETWORK` | DNS, proxy, firewall or untrusted TLS | Ask admin to verify network and certificates |
| `TRIVY_DB` | CVE database unavailable | Check scanner DB cache and mirror |
| `DOCKER_UNAVAILABLE` | Docker daemon or worker unavailable | Run `./appsec doctor` |
| `NO_DISK` | Host or Docker disk full | Inspect storage and retention |
| `BUILDKIT` | Copa or executor failed | Review BuildKit and supported base image |
| `POLICY_FAILED` | Policy refused image | Review the actual policy violations |
| `MFA_REQUIRED` | Account needs second factor | Supply authenticator or recovery code |
| `CSRF_REJECTED` | Browser write without expected origin header | Reload the official Control Center |
| `INTERNAL_ERROR` | Unexpected backend error | Provide the displayed request ID to admin |

Admins can inspect System Health, Worker/Scheduler heartbeats and logs. Heartbeat age alone is **not** proof the worker is dead—it may be busy scanning.

Metabase at **http://127.0.0.1:3001** provides aggregated dashboards with separate authentication. MCP is optional, read-only and never necessary for manual use.
