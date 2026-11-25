# v3 Phase 1: evidence-driven remediation research

Status: experimental development, based on v2.0.0. No expansion of automatic patch execution is enabled in Phase 1.

## Findings from the v2 implementation

The input filter passes only OS findings with nonempty FixedVersion. Application findings, even with reported fixes, never reach Copa. No reported fix is a scanner observation, not proof that no vendor fix exists. Copa report-driven mode is not an all-package upgrade. Upstream also offers experimental application-level patching, with package manager/dependency limitations; validate against an exact release before enabling. Do not infer that an OS fix is compatible or available in the configured repository solely from FixedVersion.

References:
- https://project-copacetic.github.io/copacetic/website/v0.13.x/app-level-patching
- https://project-copacetic.github.io/copacetic/website/troubleshooting
- https://project-copacetic.github.io/copacetic/website/faq
- https://trivy.dev/docs/latest/guide/scanner/vulnerability/

## Read-only diagnosis from existing AppSec evidence

Run on a staging deployment of develop/v3:

    docker compose exec -T worker python -m appsecctl.cli remediation-audit --pipeline-id PIPELINE_UUID > remediation-audit.json

Existing v2 deployments can be analyzed without starting or installing v3. From the running v2 checkout, create a detached v3 worktree (choose an unused path) and export a full summary on a trusted terminal:

    git fetch origin develop/v3 --tags
    git worktree add --detach ../AppSec-v3 origin/develop/v3
    umask 077
    docker compose exec -T -e APPSEC_SUMMARY_COMPACT=false worker python -m appsecctl.cli summary --pipeline-id PIPELINE_UUID > pipeline-summary.json
    PYTHONPATH=../AppSec-v3/runner python3 -m appsecctl.remediation_audit --summary pipeline-summary.json > remediation-audit.json

This is read-only with respect to the v2 application and DB. Do not run the second Compose project beside v2 on the same daemon: existing static names/volumes can collide. Summary files contain security and infrastructure data; keep them private and share only approved/redacted diagnostics.

The output is a versioned structured contract, appsec.remediation-audit/v1, usable by a future Go module or MCP tool. It reports all finding occurrences, not unique CVEs, even LOW. Original OS-known-fix, OS-no-reported-fix, application-known-fix, application-no-reported-fix, other, and ambiguous identity are separate cohorts. The report also displays a small coverage summary. No new database tables.

New patch attempts record the SHA256 and count of the canonical exact input written to disk; historical attempts report not_recorded. The expected input is derived from the original evidence. A mismatch is a diagnostic, not evidence that the backend executed any particular update. Rescan attribution requires a successful patch, matching local image identity and linked diff. Missing target inventory gives coverage_unknown rather than no_longer_detected. A changed severity does not count as disappearance. Mixed-eligibility duplicate groups are kept separate. Rates are observational; matching scanner metadata is not proof of identical database content. Package version equality/change is evidence, not a distro version comparison or dependency conflict diagnosis.

## Offline candidate comparison harness

On an isolated host with a prepared, quiescent Trivy cache and already-loaded image candidates:

    python3 scripts/v3-benchmark.py --scanner APPROVED_TRIVY_REF \
      --db-cache /absolute/path/to/trivy-cache \
      --original ORIGINAL_LOCAL_TAG \
      --candidate APPSEC_PATCHED_LOCAL_TAG \
      --candidate UPSTREAM_PATCHED_LOCAL_TAG \
      --output ./benchmark-result

The harness resolves immutable local image IDs, copies and hashes vulnerability/Java DB files, uses separate temporary Docker save archives and per-scan cache copies, and runs a network-disabled scanner without Docker socket access or implicit pulls. It verifies DB hashes before and after scans. No image build, push, deletion, application execution or registry credential is performed. Use an approved trusted scanner already loaded locally; this tool intentionally does not replace the runtime source resolver. Prepare the candidate images separately with the existing guarded workflow or a controlled upstream experiment. The frozen offline scan may have less coverage than online scans; missing Java DB or unsupported targets fail rather than fabricate evidence. Archive ImageID must match Docker's config ID or comparison is rejected. Outputs are private local JSON (raw reports, manifest, per-candidate comparisons, summary); ensure sufficient disk space. On failure, partial outputs may exist but no final summary is written. Application compatibility and candidate lineage need separate tests.

## Controlled benchmark protocol (not run automatically)

Use a dedicated isolated test host. Never benchmark on production images or push the outputs. Select and record exact immutable image digests, exact scanner and Copa versions, platform, BuildKit version, package repository snapshots and scanner DB snapshot hashes. Preserve originals and repeat with the same Trivy cache snapshot and scan settings; disable DB updates only in this explicitly frozen experiment. Separate from the regular production refresh. Record Java DB presence/absence and scanner coverage, do not equate missing inventory with zero findings.

For each test input:
1. Original scan and package inventory.
2. v2 baseline report-guided OS patch through AppSec.
3. Direct upstream report-guided OS patch using the same filtered JSON, approved sources and executor; no push. Compare input hash, package changes, CVEs and errors. Do not bypass source policy to make a benchmark succeed.
4. Evaluate broader package upgrade and experimental language paths only in isolated, explicitly authorized experiments after verifying exact upstream flags and safety. Record package dependency resolution and source availability.
5. Independently rescan every candidate with the frozen scanner/DB, inspect config/entrypoint/user/healthcheck, run image-specific smoke tests and compare package inventories. No automatic candidate promotion.

Matrix: Debian/Ubuntu, Alpine, RPM-based OS, Python, Node.js, Java and Go workloads, distroless and scratch/unsupported cases. Record unsupported and unavailable samples rather than fabricate results.

Acceptance: compare OS-known-fix cohort disappearance under identical evidence, no introduced high/critical findings, no functional regression, verified image identity, documented reasons for residual findings. Do not set an arbitrary universal fix percentage. A reported version is not proof of an installable fix; use package-manager-native version semantics.

## Next phases (not implemented)

1. Run the new frozen-DB candidate comparison harness on real images; implement controlled candidate generation and investigate actual residual groups.
2. Typed remediation planner and backend strategy interface. Separate OS, language, base migration and source rebuild. AI proposals never execute arbitrary commands.
3. MCP read-only evidence tools, optional provider, structured validated plan, deterministic verifier and human approval. Never send repository credentials or raw secrets to AI.
4. Port tested contracts incrementally to Go. Keep API socket-free; shared binary with separate executor role. Retain PostgreSQL and BuildKit isolation; optional S3/BI/reverse proxy profiles.
5. Regression, compatibility, security and migration acceptance before v3 release.
