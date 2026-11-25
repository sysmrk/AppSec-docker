# Registry governance — v2

Settings → Registries separates pull sources from publication destinations. Trusted pull sources control which repository mirror is tried first; publication registration is an explicit host/port and optional Project with allow_push. These are separate controls.

## Configure publication

Register e.g. harbor.example.org:443 as a host, enable Push only for approved scope, and separately provision scoped Docker credentials in the worker execution environment. Metadata does not log in to a registry or verify TLS. REGISTRY_HOST and PATCHED_REPOSITORY set the suggested default destination; the reviewer can choose another complete approved registry/repository:tag per workflow.

Full platform startup includes local patch execution. The guided scan requires no Harbor or write credentials. Approve local patch preparation only when verified OS fixes exist, then review the independent rescan and advisory. A not-recommended result requires a documented risk reason. Approve the exact destination separately; APPSEC_REQUIRE_SECOND_APPROVER=true requires a different authorized reviewer. Worker revalidates authorization and image identity, pushes once, pulls by manifest digest and verifies the local image ID. Failed verification or ambiguous push must be reconciled manually.

Choose Keep patched image locally if no registry output is needed:

```bash
docker save -o patched.tar EXACT_LOCAL_IMAGE_TAG
```

This requires the same Docker daemon as the worker. Prepared images are not portable across hosts without staging/affinity. Deleting workflow history never deletes remote published images.

## Optional Harbor

Harbor is not started by AppSec. On an approved host, set unique random passwords of at least 16 characters via a trusted shell, then run ./scripts/harbor.sh install and ./scripts/harbor.sh login. Configure certificates, scope, retention and registry access before use. Avoid using an insecure registry in production. See [source priority](image-source-priority.md) and [workflow](workflow.md).
