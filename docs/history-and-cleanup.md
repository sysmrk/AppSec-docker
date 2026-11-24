# Delete pipeline history and associated evidence

The Overview shows ten latest image workflows, deduplicated from manual workflows, pipeline runs and standalone queued jobs. Repository security jobs remain separate. My workflows is the full image history with server-side pagination (20 per page); select eligible completed/failed workflows on the current page for export or administrator-only permanent deletion. Active or unfinished approval workflows cannot be bulk-selected. Changing pages clears selections.

Admins may open a finished pipeline in Results or My workflows, select Delete this pipeline history, and type DELETE. The server requires an exact pipeline-ID confirmation and rejects deletion while related jobs are queued or running.

This removes the selected pipeline's workflow, jobs, scan/CVE, policy, patch, diff, report/artifact and orphan image-inventory rows from PostgreSQL. Recorded evidence under /reports and the configured S3/MinIO bucket is also deleted. When evidence cleanup fails, the database deletion is rolled back and the error remains visible; previous partial file deletion may still have occurred.

Local patched image tags are queued for removal by the image Worker because the API is deliberately denied Docker Socket access. Inspect GET /appsec-api/api/maintenance/image-removals and retry failed removals via POST /appsec-api/api/maintenance/image-removals/retry. A queued removal is not yet a completed Docker cleanup; image layers shared by other tags may remain in Docker storage.

Security audit logs are retained. Published images in remote registries are not silently deleted. Shared base-image Docker cache, downloaded copies and backups are also outside this operation. Remote image deletion needs a separate explicit authorization and a full digest/destination confirmation. The control is not equivalent to backup erasure.

## Overview selection

Select individual completed/failed image workflows or the header checkbox. Export downloads HTML for one workflow or a ZIP for multiple workflows, using current DB data and per-resource authorization. Delete selected is admin-only and requires typed DELETE confirmation. It invokes the existing per-pipeline purge sequentially and reports partial failures. Active pipelines cannot be removed. The purge removes workflow/job rows, findings, comparisons, policies, artifacts and reports from live application storage, and queues local patched tag removal. Shared images, remote published registry images, audit logs, backup copies, storage versions/retention and externally exported reports are not erased. Versioned object storage requires an independent approved retention/lifecycle policy. External storage operations and DB transactions are not globally atomic.

### Patch tooling resolution

Copa v0.14.1 may request Debian `stable-slim` even for a versioned target. AppSec resolves the tooling image for the detected Debian major release through the configured pull-source priority, then maps both Copa's cached and Docker Hub stable aliases to that approved reference. Unapproved sources remain denied. Worker logs record `COPA_HELPER_MAPPING`; this does not change package-manager egress or authorize a publication retry.

BuildKit v0.29.0 has a source-policy formatting issue: EXACT conversions can leave the original identifier unchanged. AppSec uses anchored, escaped REGEX selectors for CONVERT only; ALLOW retains exact references and additionally permits the anchored tag@sha256:<64 lowercase hex> form for each approved unpinned tag. The default DENY remains. CI exercises actual BuildKit conversions and rejects unrelated/near-match references. This does not permit direct access to the original helper registry.

The frontend and LLB may evaluate the same image twice, first by tag and then by tag plus resolved manifest digest. Both are covered without granting repository-wide access. Explicitly digest-pinned inputs remain exact. The tag-based allowlist is not a content pin or a substitute for image identity verification.
