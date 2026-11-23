# Registry Management and Safe Publication

## Register a destination

In AppSec Control Center **Registries**, an Admin records an HTTPS Registry hostname (and optional port), alias, optional Project scope, and explicit `allow_push`. No passwords are stored here. For publication, the registered destination host must match `REGISTRY_HOST` from `.env` (and the configured `PATCHED_REPOSITORY` determines repository path). Worker Registry login/credentials must be provisioned separately.

Example trusted Registry configuration:
```env
REGISTRY_HOST=harbor.example.org:443
PATCHED_REPOSITORY=security/appsec-patched
```

**Default scan-only requires no Harbor.** To allow controlled local patch preparation, isolate the Worker and run `./appsec start --patching`.

## Human review sequence

1. Scan original image, review CVEs/Policy/SBOM.
2. Explicitly approve `Prepare patch & rescan`: Copa/BuildKit produces a **local** image, no Push.
3. Trivy scans the prepared image and evaluates the final Policy.
4. Review fixed, remaining and new vulnerabilities. If Policy does not pass, publication is **blocked**.
5. Choose `Finish without publishing` or explicitly `Approve registry Push`. Optionally require two distinct approvers with `APPSEC_REQUIRE_SECOND_APPROVER=true`.
6. The Worker tags and pushes to the registered, approved destination **once**; it never silently retries ambiguous partial uploads.

The CLI command `./scripts/appsecctl.sh run IMAGE --patch` prepares a local patch, rescans it and evaluates policy. Use the guided workflow for approved Registry publication.

## Harbor helper (optional)

To install a local Harbor, pass **unique random** credentials at least 16 characters long; the helper has no acceptable default:
```bash
export HARBOR_ADMIN_PASSWORD='REPLACE_WITH_A_RANDOM_SECRET'
export HARBOR_DB_PASSWORD='REPLACE_WITH_A_DIFFERENT_RANDOM_SECRET'
./scripts/harbor.sh install
./scripts/harbor.sh login
```
The helper uses `--password-stdin`, and the credentials must exist in the correct Worker/Docker environment for actual Push. Never publish untrusted registries or assume a browser login grants Docker permissions.

## Scale and artifact retention

Local prepared Docker images stay on the Worker daemon, not in PostgreSQL. A second Worker on a different host cannot automatically publish them. Multi-host/Enterprise requires Worker affinity or a dedicated staging registry and controlled Promotion design, with eventual digest signing and immutability controls. Registry metadata alone does not validate TLS or authenticate to the host.


## Per-workflow destination (November 2026)

After a successful local patch and post-patch rescan, the reviewer may enter a full image destination such as `harbor.example.org/security/nginx:patched-2026` in the final approval screen. The exact destination hostname must exist in **Registries** with `allow_push=true`, and the Worker must have corresponding scoped push credentials. API validates the destination and the Worker checks authorization again immediately before `docker push` (permission revocation is effective while queued). If the recommendation is `not_recommended`, it is a warning, not an automated denial: an authorized human must explicitly approve the destination. `Keep patched image locally` performs **no push** and retains the local Docker tag shown in the UI; an operator can export it on WSL with `docker save -o patched.tar IMAGE_REF` if an archive is needed. Never use history deletion as a way to delete a previously published remote image.
