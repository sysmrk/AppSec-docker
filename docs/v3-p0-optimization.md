# P0: Debian repository availability and nginx optimization lab

Go migration and MCP/AI expansion are deferred. The initial P0 scope is a host-side, explicit lab CLI. It does not alter the v2 or v3 production workflow, database, approvals or remote registry. Only trusted local Linux/amd64 images in a disposable lab are supported.

## Observed benchmark (user-run, 2026-11-25)

Trivy 0.76.2, frozen DB snapshot, nginx 1.31.10 / Debian 13.8: 454 original findings, 453 after Copa, 358 after manual removal of nginx-module-image-filter, no new findings. Severity before/Copa/debloat: CRITICAL 1/1/1, HIGH 72/71/63, MEDIUM 130/130/111, LOW 178/178/163, UNKNOWN 73/73/20. OS inventory 146/146/111. Default configuration and HTTP 200 smoke test passed. This is removal of optional functionality, not a fix for the retained packages, and not proof of compatibility with a deployed workload. Historical OCI layers retain removed bytes. The critical finding remains. APT simulation with TUNA signed metadata found only libzstd1 upgradable. No general claim of a 21% reduction is justified.

## Commands

Run from the v3 checkout on the lab host, with PYTHONPATH=runner.

    python3 -m appsecctl.apt_optimization availability --image sha256:IMAGE_CONFIG_ID --mirror tuna --confirm-isolated-lab

Explicitly selects one mirror pair (tuna or debian). The temporary container refreshes signed APT metadata for Debian bookworm/trixie only, then simulates dist-upgrade. No packages installed, no fallback, no live configuration changed. Only run with approved network egress; the Docker runtime is not a firewall. Repository errors fail the probe; they do not imply no available patch. The initial probe uses temporary configuration, not a persisted package-source priority policy or a Copa egress override.

    python3 -m appsecctl.apt_optimization plan --image sha256:PATCHED_CONFIG_ID --report candidate-1.json --remove nginx-module-image-filter --confirm-isolated-lab > plan.json

Use a verified raw benchmark scan of that same image. Repeat --remove for explicitly approved nginx-module-xslt or nginx-module-geoip. The offline simulation refuses installs/upgrades, essential/protected/required/important packages, non-approved manually installed packages, nginx core and a conservative core dependency denylist. Counts are an estimate using package name/version matching. Inspect the entire closure and confirm application owner acceptance, including removal of optional functionality.

    python3 -m appsecctl.apt_optimization build --plan plan.json --report candidate-1.json --approve-sha256 PLAN_SHA256 --confirm-isolated-lab > candidate.json

The digest binds the plan, not an authenticated approval identity. The local operator must review and approve it. The build re-runs the plan, checks exact simulated removal names inside the build, checks dpkg audit/nginx -t, verifies the base layer prefix, runtime config and exact post-build package inventory. No automatic promotion, no push. Build uses a unique local tag and the default Docker builder, with no RUN network; the builder's metadata resolution is not a firewall, so isolate the host. A failed build can leave a local candidate for manual reconciliation. Independently rescan the candidate using the frozen benchmark tool and execute workload-specific smoke tests before any promotion. This tool does not reconstruct historical layers.

## Remaining P0

Persisted per-ecosystem approved mirror configuration and priority handling, actual Copa package-manager mirror propagation, native alternative upgrade executor, generic dependency analysis beyond nginx, integrated workflow/RBAC/approval, verified candidate ranking and report integration remain outstanding. No general automated removal policy.

## Candidate security review

    PYTHONPATH=runner python3 -m appsecctl.candidate_review --results /path/to/benchmark/results > review.json

Recompute comparison from raw reports, cross-check saved summaries and scanner/image IDs, count per severity and package-name additions/removals/version changes. Reject candidates with unknown coverage, introduced findings, Critical/High/Unknown count regression or no net reduction from preferred-for-review selection. Rank eligible candidates by Critical, High, Unknown, Medium, Low, then fewer removed package names. This conservative order does not represent exploitability or business risk; no functional or publication authorization is inferred. Raw benchmark files are local trusted inputs, not signed attestations. Report separately findings absent on package names no longer present, not automatically fixed by a patch. The original known-fix result and 95 additional disappearances are distinct.

## Ordered repository and inventory review

    PYTHONPATH=runner python3 -m appsecctl.apt_repository_review availability --image sha256:CONFIG_ID --mirror tuna --confirm-isolated-lab

Repeat --mirror debian only if official Debian egress is explicitly approved. Known metadata transport errors can advance to the next explicit mirror; signature, TLS, unexpected errors and timeout stop the probe. All mirrors unavailable returns counts=null and nonzero exit. This is a lab priority list using built-in endpoints, not persisted enterprise configuration or a Copa egress policy.

    PYTHONPATH=runner python3 -m appsecctl.apt_repository_review inventory --image sha256:CONFIG_ID --report candidate-1.json --confirm-isolated-lab

Compare native dpkg inventory with scanner inventory and finding versions without altering evidence. The approved 43-package removal plan built successfully on the user lab (candidate f93c13782f1ee44008ffd566f34bfae885664e54e8f788515cff3d89dec4c12a). Its independent rescan and runtime smoke test are still pending. No automatic publication.
