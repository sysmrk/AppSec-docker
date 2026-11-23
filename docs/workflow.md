# Manual workflow state machine and approvals

The default path is read-only with respect to registries; Docker may still pull images and scanner feeds.

```text
Create -> Queued -> Scan original -> SBOM -> Policy -> Review
                                                    |        |
                                                 Finish    Prepare patch [human approval #1]
                                                    |        |
                                                 Complete  Copa / local image
                                                             |
                                                        Rescan + SBOM
                                                             |
                                                     CVE diff + Policy
                                                             |
                                            +----------------+----------------+
                                            |                                 |
                                        Failed policy                     Policy passed
                                            |                                 |
                                      Block publication                  Final review
                                            |                                 |
                                      Finish locally            +------------+------------+
                                                                |                         |
                                                           Keep local only         Publish [approval #2]
                                                                |                         |
                                                             Complete       Approved registry, single push
                                                                                           |
                                                                                  Published / uncertain
```

**First approval** authorizes *local patch preparation*, not publication. **Second approval** authorizes a Registry write only after a successful patched scan and policy; the destination must be registered with `allow_push`. Optional `APPSEC_REQUIRE_SECOND_APPROVER=true` requires the publication authorizer to differ from the patch reviewer. API and Worker validate server-side, not just JavaScript.

State data resides in `manual_workflows`, `pipeline_jobs`, `patch_runs`, `scan_runs`, `scan_diffs`, `policy_results` and `audit_logs`. Statuses include queued, scanning, awaiting_approval, patch_queued/running/failed, awaiting_publication, publication_blocked, publish_queued/publishing/published/publish_failed, completed_without_publish, completed and canceled. API decision actions: `finish`, `approve_patch` (requires `confirm_patch=true`), `approve_publish` (requires `confirm_push=true`), `skip_publish`, `cancel` (only queued).

A publication job has `max_attempts=1`; a failed or uncertain registry push must be reconciled manually. The worker may need access to its local prepared image between approval steps. In multi-host deployments, use host affinity or a trusted staging registry with controlled promotion before scaling horizontally; local Docker caches are not portable.

CLI/CI flows still support scan-only defaults via `./scripts/appsecctl.sh run IMAGE` and `./scripts/appsecctl.sh ci image IMAGE`. The explicit `--patch` option prepares and rescans a local image. Registry publication requires a separate approval in the Control Center workflow.

No synthetic CVEs, placeholder image states or test results are shown to users. The preflight check deliberately marks actual pull/authentication as **unverified** until a real scan.
