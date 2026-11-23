# Strict priority image sources

In Control Center, open Registries > Trusted image pull sources. Add each mirror by hostname (for example hub.hamdocker.ir or docker.arvancloud.ir), alias and numeric priority. Priority 1 is attempted first; on a failed docker pull the Worker tries 2, then 3. A Docker Hub-style unqualified nginx:1.27-alpine becomes host/library/nginx:1.27-alpine. The originally requested image remains in the pipeline, while Trivy and Copa receive the selected mirror reference.

## Fail-closed semantics

As soon as any source has been configured, AppSec must not fall back to Docker Hub. If all configured sources are disabled, scanning fails closed. With no source policy ever configured, direct pulls remain available for backward compatibility. The source policy is global to this deployment; only administrator accounts may change it. Scope network egress at the firewall as a second defense.

Pull sources are distinct from publishing destinations. Registry credentials are never saved by the source form. An image can be pulled successfully by the Docker daemon but still fail inside BuildKit because Copa uses its own registry access. Check BuildKit credentials and outbound HTTPS separately. The scanner image, Trivy DB, and BuildKit image also need configured mirrors. Current mirrors preserve path/tag but do not enforce cross-mirror digest equivalence; use digest-pinned inputs for stricter provenance.

## Troubleshooting

Check readiness shows the ordered candidates without claiming network access. My workflows displays error code SOURCE_PULL_FAILED, source aliases, order, exit status and a sanitized HTTP/network diagnostic. Use ./appsec logs worker, or test the exact mirror reference with docker pull on the WSL host. Do not assume an HTTP 403 means that the target image is missing.
