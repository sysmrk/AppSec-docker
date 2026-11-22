# Image Inventory, Registry Manager and Diagnostics

## Image Inventory

The **Images & scans** screen queries real images, pipeline runs and Trivy results from PostgreSQL. Authorized users can:
- Search by image reference, repository, tag or digest
- See the most recent scan state and Critical/High counts
- Browse actual scan history for an image, ordered by last run
- Open a pipeline and view CVEs, Policy and downloadable artifacts
- Compare two distinct scans: fixed, still-present and introduced CVE/package/target entries

Inventory lists are paginated and comparison details are bounded. Counts represent matching persisted scan data only, not an external live registry inventory. Images that have never been scanned do not appear. Legacy unassigned scans may remain outside the newer creator-private manual workflow model; address tenancy in a staging acceptance review.

## Registry Manager

An Admin can visit **Registries**, register an alias and HTTPS hostname with optional port, associate a Project and explicitly toggle `allow_push`. HTTPS-only host syntax rejects passwords/paths/queries.

**Important:** Registry Manager stores configuration metadata only. It **does not** store Registry passwords, create a Docker login, query arbitrary registry URLs, verify certificates or allow publication by itself. Docker login/credential management remains a Worker/secret-manager responsibility. A separate human publish approval and successful final policy are also required.

The actual destination configured using `REGISTRY_HOST` and `PATCHED_REPOSITORY` must exactly match an approved Registry hostname. The current release uses one target destination per deployment; dynamic per-workflow registry routing is a future enhancement.

## Preflight Check

The **Check readiness** button provides evidence-based checks:
- Image reference syntax validity
- Presence of matching registered Registry metadata
- Recent Worker heartbeat
- Image pull status **unverified** until an actual Trivy attempt

This is deliberately not a Docker registry login test. The worker may be busy, private, offline or subject to egress controls. Do not interpret a checked form as an authenticated Registry connection.

## Actionable errors

Errors expose stable codes with a brief explanation and a safe next action, without returning raw tokens, passwords or subprocess stderr. The relevant Job ID and HTTP request correlation ID help admins find trusted logs. Common codes include `REGISTRY_AUTH`, `REGISTRY_NOT_FOUND`, `REGISTRY_NETWORK`, `TRIVY_DB`, `DOCKER_UNAVAILABLE`, `NO_DISK`, `BUILDKIT`, `TIMEOUT`, `POLICY_FAILED`, `INPUT_INVALID`, `CSRF_REJECTED`, `MFA_REQUIRED` and `INTERNAL_ERROR`.

Only a failed initial **scan-only** workflow has an in-UI create-new-scan retry. An ambiguous Patch or Registry Push must be reconciled manually. Never blindly retry a partially completed publication.
