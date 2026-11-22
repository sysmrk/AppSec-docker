# Real Image Security Workflows

AppSec offers two entrypoints:

1. **Manual Control Center** for users without CI/CD, with persisted human review and consent
2. **CLI/API** for CI/CD integrations and batch automation

Both use PostgreSQL jobs, Trivy, CycloneDX SBOM and the security policy engine. There is no demo mode or generated fixture data.

## Manual workflow: start to finish

```text
Create workflow (Image + optional Project)
    |
    v
Queued scan -> Trivy Original Scan -> CycloneDX SBOM -> Policy -> Report
    |
    v
Awaiting explicit user decision
    |                                    |
    | Finish without modifying image    | Approve patch + registry push
    v                                    v
Completed, report retained       Single-attempt continue_patch job
                                        |
                                        v
                           Copa + opt-in BuildKit -> Registry Push
                                        |
                                        v
                           Trivy Patched Rescan -> SBOM -> CVE Diff
                                        |
                                        v
                                Final Policy + Report
```

**Only the first half runs automatically.** Patch/Push must be enabled by the administrator with `./appsec start --patching` AND explicitly confirmed in the UI. Approval is recorded with user ID and timestamp. A potentially partial registry write is **never automatically retried** by the continuation job.

Use Control Center **New manual scan** → **My workflows**. You can see queue state, scan counts, file links and pending human decisions. Image input is a **registry reference**, not an archive upload.

## Manual workflow API

```bash
# Create a scan-only manual workflow
curl -X POST http://127.0.0.1:8080/appsec-api/api/manual-workflows \
  -H "X-API-Key: $APPSEC_API_KEY" -H 'Content-Type: application/json' \
  -d '{"image":"registry.example.com/team/api:1.4.0","project_id":null}'

# List authorized workflows
curl -H "X-API-Key: $APPSEC_API_KEY" \
  http://127.0.0.1:8080/appsec-api/api/manual-workflows

# Inspect one workflow; use returned id
curl -H "X-API-Key: $APPSEC_API_KEY" \
  http://127.0.0.1:8080/appsec-api/api/manual-workflows/WORKFLOW_UUID

# Save the decision without patching:
curl -X POST -H "X-API-Key: $APPSEC_API_KEY" -H 'Content-Type: application/json' \
  -d '{"action":"finish"}' \
  http://127.0.0.1:8080/appsec-api/api/manual-workflows/WORKFLOW_UUID/decision

# Advanced: requires --patching and explicit push approval
curl -X POST -H "X-API-Key: $APPSEC_API_KEY" -H 'Content-Type: application/json' \
  -d '{"action":"approve_patch","confirm_push":true}' \
  http://127.0.0.1:8080/appsec-api/api/manual-workflows/WORKFLOW_UUID/decision
```

Only Admins and Operators with write permission can decide; viewers cannot. Unassigned manual workflows are private to their creator/admin. Members who lose Project access also lose access to that Project's workflows. Invalid or duplicate decisions are rejected.

## CLI and CI/CD (noninteractive)

```bash
./scripts/appsecctl.sh run registry.example.com/team/api:1.4.0
./scripts/appsecctl.sh ci image registry.example.com/team/api:1.4.0
./scripts/appsecctl.sh enqueue registry.example.com/team/api:1.4.0
```

These default to **scan-only**. The advanced one-shot CLI uses `run ... --patch` only with an isolated executor and explicitly configured registry permissions. The public API `POST /appsec-api/pipelines` requires `mode=patch` plus `confirm_patch=true` to execute patching; it is separate from the guided workflow.

Scheduled scans also default to scan-only. Existing queued jobs from before the migration may preserve prior patch mode, but Workers now independently enforce the patch feature flag before any write.

## Outputs

- Original and optional patched `scan_runs` with severity counts
- Vulnerabilities with package, installed/fixed versions and severity
- HTML report and CycloneDX SBOM
- Policy results and violations
- Optional patch run and before/after `scan_diffs`
- Manual workflow approval audit trail
- Aggregate analysis in Metabase, never an approval mechanism
