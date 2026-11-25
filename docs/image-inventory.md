# Image inventory and readiness — v2

Images & scans is a PostgreSQL-backed inventory of actually scanned images, not live registry discovery. Search image references, repository names, tags or digests; inspect history, severity and execution status, and open the selected report. Compare two distinct accessible scans by vulnerability/package/target. Comparison rows are bounded; use raw evidence for complete investigation. Scanner and DB snapshots may differ; absence in a rescan is not proof of remediation.

My workflows is the complete paginated workflow history, including unfinished approvals. Overview displays the latest ten image workflows and recent repository jobs. Export and admin cleanup apply to idle pipelines; queued/running jobs and rows without a pipeline are not eligible.

Settings → Registries configures ordered pull sources separately from approved publication hosts and Project scope. The exact destination can vary per workflow. No Registry passwords are stored in this metadata. Check readiness validates input, matching registry metadata and real heartbeat, not remote authentication or existence. A real pull is required.

Legacy unassigned pipelines can have broader access than creator-private manual workflows. Assign Projects and validate tenant isolation before production. Use the actual job ID and sanitized error code for diagnostics. See [user guide](user-guide.md), [registry](registry.md) and [reports](consolidated-report.md).
