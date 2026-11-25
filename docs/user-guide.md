# Operator guide — v2

## Access

Open http://127.0.0.1:8080 on the host. Retrieve the initial admin credentials using ./appsec credentials on a trusted terminal. Change a temporary password when prompted. If MFA is enabled, provide a fresh authenticator code or unused recovery code.

## Scan an image

1. Under Settings → Registries an admin configures source priority. For publication, register the destination separately.
2. Select Image scan, enter an image name/tag/digest, choose Project if applicable and Check readiness. This checks configuration and heartbeat, not actual authentication or pull availability.
3. Start the scan. My workflows shows progress and diagnostics. The initial job pulls the image, scans OS and application vulnerabilities, generates SBOM and saves evidence.
4. Review findings and patch eligibility. If no OS fix is known, select Finish without patching. Application dependencies require separate updates/rebuild.
5. Approve Prepare patch & rescan to create a local image. Review before/after evidence and recommendation.
6. Keep patched image locally or approve a complete registered registry destination. A not-recommended image requires a documented reason; a distinct second reviewer may be required. Verify published digest and timestamp in the report.

No automatic patch/push follows initial submission. A failure or uncertain registry write requires administrator reconciliation. Do not blindly retry. Use a new scan for failed initial execution.

## Repository scan

Enter an allowed HTTPS repository URL. Public repositories need no credentials; for private repositories supply username and scoped read-only PAT/password in the separate fields. Never embed credentials in a URL. Quick/standard use a shallow checkout and directory scan; strict/release scan fetched Git history. Results are redacted and do not show actual secret values. Rotate exposed credentials separately.

## History and downloads

Overview shows recent work. My workflows shows 20 entries per page. Open a selected workflow or scan to view report details. Export selected downloads HTML or ZIP with UTC names. Idle workflows, including those awaiting approval, are selectable; active jobs and rows without a pipeline are not. Admin deletion discards pending approvals and live evidence, not audit records or remote images. See [history](history-and-cleanup.md).

Images & scans shows only scanned inventory, not every image in a registry. Compare two recorded scans; different scanner/DB versions may affect differences. Approvals lists pending decisions for authorized projects.

## Settings

Tool updates, Registries, Users & access, Projects & policies, System health, Integrations and My profile & MFA are grouped here. Administrative categories require admin. Manage post-patch advisory thresholds under Projects & policies. Accounts have local roles, Team membership and optional authenticator MFA; recovery codes are displayed once. See [identity](enterprise-features.md).

## Troubleshooting

| Code / symptom | Action |
| --- | --- |
| SOURCE_PULL_FAILED / REGISTRY_AUTH | Check ordered sources, mirror path, credentials, TLS and worker logs |
| TRIVY_DB / TRIVY_JAVA_DB | Check approved OCI database repositories and cache |
| SCAN_STAGE_TIMEOUT | Identify timed-out stage and named scanner; adjust timeout for large workloads |
| SCAN_EVIDENCE_INVALID | Verify image identity and OS inventory; submit a fresh scan |
| NO_FIXABLE_OS | Finish without patch; review remaining risk |
| PATCH_SOURCE_POLICY | Check approved helper mappings and BuildKit network |
| Tool check/update failed | See Settings → Tool updates error and [tool updates](tool-updates.md) |
| Queue appears stuck | Check actual job status, logs and worker processes; heartbeat alone is insufficient |

Metabase provides separate-login analytics; MCP is optional read-only. Neither is an approval interface.
