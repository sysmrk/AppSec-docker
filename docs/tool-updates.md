# Tool update manager — v2

Settings → Tool updates is admin-only. The scheduler checks official GitHub stable releases every six hours and on Check now (asynchronous). Apply/Retry update queues a version-specific installation, not an immediate browser download.

| Tool | Install method |
| --- | --- |
| Copa | Official Linux archive with SHA256 from official release metadata, version and patch-help smoke checks, atomic replacement in shared versioned volume |
| Trivy | Exact version tag through configured approved registry sources, version check |
| Gitleaks | Exact version tag through configured approved registry sources, version check |

Failed installation retains active version. Latest stable after check_failed is last-known data, not a fresh check. Version-tag checks are not image digest/signature pinning or compatibility certification. BuildKit and infrastructure versions are deployment-managed. Trivy vulnerability DB refresh is independent of scanner binary release updates.

## Network errors

GitHub metadata (api.github.com) and assets (github.com, release-assets.githubusercontent.com, objects.githubusercontent.com) use verified HTTPS and allowlisted redirects. Transient failures retry up to three attempts. Diagnose DNS, TLS, connection timeout, HTTP status and rate limit. Use APPSEC_TOOL_HTTPS_PROXY and APPSEC_TOOL_CA_FILE (mounted PEM path inside scheduler) when needed. Never disable TLS verification.

## Offline Copa asset transfer

If an official stable release has already been discovered, download its exact archive on a trusted connected host and copy into the scheduler inbox. Example for Linux amd64 v0.15.0 (replace with approved version and architecture):

```bash
docker compose exec -T scheduler mkdir -p /tool-updates/inbox
docker compose cp copa_0.15.0_linux_amd64.tar.gz scheduler:/tool-updates/inbox/
```

Official tag metadata is cached per version. If necessary, a trusted admin can obtain exact JSON from https://api.github.com/repos/project-copacetic/copacetic/releases/tags/v0.15.0 using validated HTTPS and stage it:

```bash
docker compose exec -T scheduler mkdir -p /tool-updates/release-metadata/copa
docker compose cp release.json scheduler:/tool-updates/release-metadata/copa/0.15.0.json
```

Only a discovered and approved version can be queued through UI. Do not forge metadata or replace checksums. SHA256 mismatch refuses installation; remove invalid staged files. This is administrator-controlled trusted transfer, not independent signature verification.

Back up tool-updates volume and tool_updates DB records together. No UI rollback workflow currently exists; rehearse recovery with backups and isolated staging. Check a real scan and local patch/rescan before approving a new version for sensitive workloads.
