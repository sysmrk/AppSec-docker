# Optional Harbor / Patch and Push Setup

**Harbor is not necessary for scan-only mode.** Default `./appsec start` does not launch privileged BuildKit and does not push images.

## Existing enterprise registry

Configure `.env`:

```env
REGISTRY_HOST=harbor.example.com
PATCHED_REPOSITORY=security/appsec-patched
```

Registry credentials must be available to the Docker daemon used by the worker. Registry authentication in a browser is not enough.

## Optional local Harbor

The local installer requires **strong explicitly configured credentials**; it no longer accepts the old known default passwords.

```bash
export HARBOR_ADMIN_PASSWORD='USE_A_UNIQUE_RANDOM_PASSWORD_OF_AT_LEAST_16_CHARACTERS'
export HARBOR_DB_PASSWORD='USE_ANOTHER_UNIQUE_RANDOM_PASSWORD_OF_AT_LEAST_16_CHARACTERS'
./scripts/harbor.sh install
./scripts/harbor.sh login
```

The login helper uses `--password-stdin` rather than exposing a password on the Docker CLI command line. Avoid storing production secrets in shell history. Use HTTPS and trusted certificates for remote registry communication.

## Explicit patch enablement

```bash
./appsec start --patching
```

BuildKit is a privileged optional Compose profile; only start it on isolated hosts. In Control Center choose **Scan image → Show advanced options → Scan + Patch + Push + Rescan** and confirm.

CLI advanced use:

```bash
./scripts/appsecctl.sh run registry.example.com/team/service:1.4.0 --patch
```

Copa may fail to patch unsupported packages. Inspect the final scan and policy result before promoting an image. Consider signing with Cosign, immutable registry tags, short-lived credentials and digest pinning.

See [workflow](workflow.md) and [security review](security-review.md).
