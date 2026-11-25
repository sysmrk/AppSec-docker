# CI/CD security gates — v2

Manual workflows and CI gates serve different purposes. The browser original scan does not enforce thresholds; post-patch recommendation is advisory, with documented risk acceptance for publication. Explicit CI commands enforce thresholds and return nonzero on failure. A successful scan is not necessarily a successful security gate.

## Image gate

On an initialized trusted AppSec execution host:

```bash
./scripts/appsecctl.sh ci image nginx:latest
```

To evaluate a local patched image, add --patch. This does not push. If no OS fix is known, the original verified evidence is evaluated. If a patch scan exists, the final patched evidence is evaluated, not an earlier successful original. Invalid/missing verification and execution failure fail closed.

Set the CI environment thresholds in the deployment .env (runner receives these via Compose):

```dotenv
POLICY_MAX_CRITICAL=0
POLICY_MAX_HIGH=0
POLICY_MAX_MEDIUM=999999
POLICY_MAX_LOW=999999
POLICY_MAX_UNKNOWN=0
CI_MAX_HIGH=0
```

The explicit image gate uses POLICY_MAX_* from the runtime environment independently of UI advisory policy. Secret CI uses CI_MAX_HIGH. LOW remains in evidence and counts despite the standard report display filter.

## Repository gate

```bash
./scripts/appsecctl.sh ci security secrets https://github.com/example/repo.git --profile strict
```

Returns nonzero on scan failure or excessive high findings. Use approved hosts and scoped credentials via the supported repository workflow when private; the direct CLI does not accept the browser's transient credential parameters.

## CI integration

Run from a trusted self-hosted runner with access to the initialized AppSec Compose project. Do not give an untrusted pull request Docker socket access. Example GitHub Actions step, applicable equally as a shell stage in GitLab or Jenkins:

```yaml
- name: AppSec image gate
  run: |
    cd /opt/appsec/AppSec-docker
    ./scripts/appsecctl.sh ci image "$IMAGE_REF"
```

A central REST integration may enqueue POST /pipelines and poll job/pipeline state, but that reports execution only; it is not equivalent to the explicit CI severity gate. Integrate policy evaluation deliberately rather than treating HTTP/job success as approval. Never automatically retry ambiguous publication; registry publication uses the separate human workflow.

Pin tool/image references for sensitive pipelines and preserve raw evidence. CI tests in this repository validate contracts and selected real components; do not infer full infrastructure acceptance.
