# v3 Phase 2 — isolated candidate generation (experimental)

Do not run on the existing v2 or production host. The explicit CLI lab is not part of the web workflow, has no publication action, writes no pipeline state and does not accept AI-generated commands. It targets a native linux/amd64 staging daemon and exactly Copa 0.15.0. A real build/benchmark is required before considering UI integration.

Prerequisites: isolated v3 deployment, approved registry and package-manager egress, verified original scan, exact immutable single-platform source manifest in the same approved repository, and its matching image loaded locally. Index digests are rejected. A child manifest digest can be supplied only if its config digest matches the saved original image. Do not use an insecure registry or disable signature checks. Configure strict sources and helper mappings; a missing policy fails closed. The LLB policy is not a firewall.

On the isolated v3 worker:

    docker compose exec -T -e APPSEC_ENABLE_REMEDIATION_LAB=true worker \
      python -m appsecctl.remediation_lab --confirm-isolated-lab \
      --scan-id ORIGINAL_SCAN_UUID \
      --source APPROVED_REPO@sha256:SINGLE_PLATFORM_MANIFEST_DIGEST \
      --strategy os_targeted > targeted.json

Repeat with --strategy os_comprehensive > comprehensive.json. The targeted mode uses the exact v2 filtered report. The comprehensive mode deliberately omits the report, applying same-release repository package upgrades as supported by upstream. Both use fixed local-only arguments, the same pinned source, mandatory source policy, no --push, no --ignore-errors, no experimental application options and a random v3-lab-* output tag. BuildKit helpers remain subject to approved source policy; package repositories, daemon redirects and upstream EOL checks need network isolation separately.

The JSON records candidate image identity, exact source, tool versions, source policy hash and targeted input hash, plus runtime configuration field changes. No claim of compatibility, security or promotion is made. If a candidate is unchanged, config is missing, source identity mismatches or the build fails, stop. Candidate tags may remain on the isolated daemon after failure; manually reconcile them. No automatic deletion or retry. A timeout may leave a daemon operation to reconcile. Runtime config checks are not functional tests.

Compare the distinct candidate references using scripts/v3-benchmark.py and the same frozen Trivy database. Run image-specific functional smoke tests before any promotion. This lab intentionally excludes automatic publication, OS-release migrations and experimental library patching. Initial scope is small to prevent hidden source fallback and multi-platform surprises.

Source checked: https://github.com/project-copacetic/copacetic/blob/v0.15.0/pkg/cmd/cmd.go and https://github.com/project-copacetic/copacetic/blob/v0.15.0/pkg/patch/patch.go.
