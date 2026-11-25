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

### Unified export and repository scans
HTML displays Critical, High, Medium and Unknown only; complete raw evidence retains LOW. Each finding has a status and before/after versions; Fixed means no longer detected, not proof of remediation. UNKNOWN is not LOW: review vendor severity/CVSS and default recommendation threshold zero. Historical downloads regenerate from persisted evidence; fields not recorded stay unavailable. Publication above advisory thresholds requires a reason; remote image identity is checked by pull-by-digest for new publications.

Repository scans accept HTTPS credentials separately. Use a scoped read-only PAT where required. Credentials are encrypted with a key derived from APPSEC_MFA_ENCRYPTION_KEY, consumed once by the worker and never logged or exported. Set SECURITY_ALLOWED_GIT_HOSTS for internal Git hosts; no redirects or TLS bypass. Standard/quick scan the checked-out tree; strict/release clone and scan Git history. Unassigned jobs are private to creator/admin.

### Tool updates
Administration → Tool updates checks official stable GitHub releases every six hours and on request. Admin approval queues updates; the scheduler installs Copa into a shared versioned volume using the official asset SHA256 and version/help checks, and pulls versioned Trivy/Gitleaks through configured sources. Updates affect subsequent jobs; failed installation preserves the previous active version. Version checks are not a full patch/scan compatibility certification. Preserve the tool-updates volume and database during backup. GitHub API/download access and an approved scanner registry source are required. The release check is distinct from Trivy vulnerability database refresh. BuildKit and infrastructure upgrades remain deployment-managed.

### Verify a deployment after Git updates
`./appsec start` stamps the checkout commit at image build, verifies the actual source fingerprints of API, worker and scheduler, restarts Nginx to refresh its upstream address, and verifies the HTTP UI build identity. `./appsec doctor` now fails on source or revision mismatch even if containers are healthy. The browser top bar displays the running build; assets are versioned by source fingerprint and served with no-store. Use `curl -fsS http://127.0.0.1:8080/appsec-api/ui/build-info` for the live identity. Local source modifications affect the fingerprint even if the Git commit is unchanged. Do not deploy during an active scan or publish.

### Patch eligibility
The full original Trivy evidence determines whether Copa has any OS findings with a known fix (all severities). Application dependencies are counted separately. Invalid evidence blocks approval; a valid zero-candidate scan offers Finish without patching and does not create a patch job. Direct patch mode skips Copa and records an audit event in this case. Older failed runs are retained as historical evidence; start a new scan-only workflow, never blindly retry a patch or publication. A skipped patch is not proof of a secure image.

### Settings and release connectivity
Settings groups Tool updates, Registries, Users & access, Projects & policies, System health, Integrations and My profile/MFA. Reports are opened from a selected scan/workflow, not an empty sidebar page. The HTML finding table omits Triage; UNKNOWN rating evidence stays in the severity cell and raw data.

Release checks retry transient HTTPS errors and show the failing stage/host and reason without disclosing proxy credentials or signed URLs. If checks fail, last-known release metadata is not presented as freshly checked. Official release metadata is cached for the exact approved version in the scheduler's tool-updates volume. Scanner updates use the previously approved version and configured OCI registry priority without a redundant GitHub check. Copa checks SHA256 against official cached metadata before installation. For restricted networks set APPSEC_TOOL_HTTPS_PROXY in .env and restart using ./appsec start --patching. APPSEC_TOOL_CA_FILE optionally points to a mounted enterprise CA file inside scheduler; normal TLS verification remains enabled.

For offline Copa asset transfer, first obtain a successful official release check (or use its previously cached metadata), download the exact official archive on a trusted connected host, then stage it with:

```bash
docker compose exec -T scheduler mkdir -p /tool-updates/inbox
docker compose cp copa_0.15.0_linux_amd64.tar.gz scheduler:/tool-updates/inbox/
````

Then choose Settings → Tool updates → Apply/Retry update. The scheduler refuses a mismatched digest or an unknown release. Do not upload arbitrary binaries or disable TLS. If the API itself is unreachable and no trusted metadata has been cached, use approved network/proxy access first. A failed download does not replace the active binary.
