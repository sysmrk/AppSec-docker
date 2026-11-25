# Consolidated reports — v2

Open a workflow or image scan to view evidence and download the current standalone HTML report. A report is available for a completed, failed or legacy policy_failed pipeline; it is regenerated from persisted data at download. My workflows supports single HTML export and multiple selected HTML reports in a ZIP.

## Read the report

- Initial and after-patch totals compare Critical, High, Medium and Unknown. LOW-only findings are hidden in the standard view but remain in raw evidence and policy counts.
- Before/after chart and a single finding table: CVE/ID, Severity, Package, Before, After, Vendor fix version, Target, Status. UNKNOWN evidence may include vendor severity/CVSS/source; no separate Triage column.
- Fixed = absent in a verified comparable rescan, not proof of remediation. Remaining = present in both. Introduced = observed only after patch. Without a verified rescan, findings must not be called fixed. Transitions to/from LOW are retained.
- Package and target comparison uses normalized target labels; raw package inventory is used where available. Findings with a known vendor fix are not necessarily patchable by the OS remediation engine.
- A missing after-patch scan is not a zero count. No known OS fixes means patch not applicable, not secure. Application packages require separate remediation.
- Post-patch recommendation is advisory; publication outcome, authorized reviewer, risk reason and destination digest/timestamp are separate evidence.

## Evidence and coverage

Trivy uses OS and library scanners, all fix statuses and explicit package inventory. Verification checks Docker image identity and OS inventory; unsupported/scratch targets may fail instead of returning clean. Raw Trivy JSON and CycloneDX SBOM remain downloadable. Original and patched image IDs must differ; remote publication is verified by pulling its manifest digest and comparing the local image ID. Legacy records missing evidence require a fresh scan before a new patch. Scanner/DB snapshots may differ between scans; absence is not proof of security or causality.

## Filenames

```text
appsec-image-nginx-latest-20261125T092928Z-<pipeline-id>.html
appsec-repository-git.example-team-api-20261125T092928Z-<job-id>.sarif
appsec-selected-reports-20261125T092928Z.zip
```

Names use a sanitized target, UTC export time, full ID and extension. ZIP members share the export timestamp. Internal storage keys remain stable for image HTML; older exports are not retroactively renamed. Raw artifacts retain their evidence identifiers.
