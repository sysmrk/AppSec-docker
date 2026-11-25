# Workflow export, retention and cleanup — v2

Overview shows ten latest deduplicated image workflows; My workflows shows twenty per page. Select idle completed/failed pipelines, including those awaiting approval. Changing pages clears selections. Active or missing-pipeline rows show why selection is disabled.

Export selected returns one HTML report or a ZIP; filenames contain target, UTC export timestamp and full identifier. Report content is regenerated from stored evidence. Access is verified for every selected pipeline. Bulk export has a size cap; select fewer reports if rejected.

## Permanent live-history deletion

Admin only: select workflow(s), choose Delete selected and type DELETE. Pending approvals are discarded. The server locks related workflow rows and refuses queued/running jobs. The per-pipeline API requires exact ID confirmation. Bulk deletion is sequential and may partially succeed.

The purge removes workflow/job records, scans, findings, patch/diff/policy rows, artifacts, generated reports and orphaned image inventory in PostgreSQL, and known files in /reports plus associated S3/MinIO objects. Storage deletion happens before database deletion; failure rolls back database changes but previously deleted files may remain missing. External storage and database transactions are not globally atomic.

Local patched tags are queued for asynchronous worker removal; inspect GET /api/maintenance/image-removals and retry failures via POST /api/maintenance/image-removals/retry. Cleanup does not guarantee physical layer erasure.

Preserved: security audit logs, remote published images, shared base image caches, backup copies, old object versions, and downloaded reports. Remote deletion and backup erasure require independent retention procedures. Never interpret this action as comprehensive forensic erasure.

## Upgrade safety

Do not deploy during active jobs or uncertain publication. Back up data and verify the deployed source fingerprint. Preserve .env, Compose overrides, encryption key, tool-updates volume and report storage. Historical Gitleaks artifacts may contain secrets; DB migration does not remove those copies. Rotate credentials and purge historical copies under policy.

See [operations](operations-runbook.md), [reports](consolidated-report.md), [source priority](image-source-priority.md) and [tool updates](tool-updates.md).
