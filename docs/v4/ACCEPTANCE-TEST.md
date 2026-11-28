# V4 acceptance gates

This is a local-only pilot. Do not merge to main or publish candidate
images until the following independent gates are satisfied. Record the
exact source commit and image digest/platform on every run.

## Native backend CI

Required: config/unit tests, database migration, scanner lab, actual
Alpine 3.22/3.23/3.24, Ubuntu Noble and each EL9 native package engine
job. The native integration fixture bypasses original scan evidence
only for engine isolation. A fixture that produces no upgrades is not
a successful build regression. A green native job is not evidence of
an end-to-end vulnerability reduction.

## WSL/UI cohort

Keep baseline image locally and use local output only. Configure flags
and trusted keys before Start; never change source policy during jobs.

| Image | Expected route | Functional smoke check |
| --- | --- | --- |
| nginx:latest | Debian when supported | nginx -t; HTTP response |
| nginx:alpine | APK if supported release and root-default | nginx -t; HTTP response |
| python:3.12-slim | Debian when supported | Python version and imports |
| python:3.12-alpine | APK if supported release and root-default | Python version and imports |
| ubuntu:24.04 | Ubuntu APT | shell and dpkg audit |
| registry.access.redhat.com/ubi9/ubi:9.4 | UBI9 DNF4 | rpm inventory and shell |
| rockylinux:9 | Rocky DNF4 | rpm inventory and shell |
| almalinux:9 | AlmaLinux DNF4 | rpm inventory and shell |
| oraclelinux:9 | Oracle DNF4 | rpm inventory and shell |
| postgres:16 | Debian where supported | database init/query in isolated disposable volume |
| redis:7 | Debian where supported | Redis ping and isolated read/write |

These tags are test inputs, not guarantees about distribution or runtime
layout. Inspect actual digest, release, platform, default user and declared
volumes. Unsupported images must be explicitly reported; the current
native pilot rejects declared volumes, non-root defaults, foreign
architectures, package additions and removals. In particular Postgres
may require a separate future validation route. Do not override these
guards merely to complete a matrix.

For each run record: resolved input and candidate IDs; Trivy and Grype
scanner IDs and DB digests; complete original and candidate counts by
severity (keep raw reports); introduced and no-longer-reported finding
occurrences per scanner; inventory coverage and exact package changes;
repository source/key/archive evidence; wall time and image size;
functional test outcome; HTML report correctness; workflow cancellation
and cleanup; errors and blockers. Keep scanner counts separate. Use the
same original image and DB/config for a V2 comparison.

Acceptance: no new findings, no coverage regression, no missing packages,
actual scanner improvement for selected trial candidates, exact inventory
and runtime config, verified workload behavior, no publication.
A no-update or unsupported result is not a fix and must not be counted as
a passing remediation. Verify UI requires no mid-run decisions, errors
are actionable, and final reports link exact images. Compare representative
cold/warm runs, not one nginx result. Workload checks must use isolated
test data and network; never production credentials.

## Repository administration

Registries > Approved external binary policy validates and downloads
a policy draft; it is deliberately not a runtime policy writer. Activate
the draft only by installing it on the worker host with independently
verified key/advisory snapshots. No network probing or signing-key
trust is conferred by draft validation. Full managed activation,
revocation, audit and multi-worker consistency need their own design
and tests before production.
