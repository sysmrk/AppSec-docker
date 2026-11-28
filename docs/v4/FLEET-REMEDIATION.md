# V4 fleet remediation scope

Owner target: roughly 1,000 projects/images. AppSec is not a distribution or
custom package factory. No custom source compilation, custom backports,
per-application patch recipes, removal/debloating, or implicit base-image
replacement in automated remediation. Existing research scripts remain
historical read-only tools; they do not authorize mutation.

## Evidence and routing

Separate discovery from executable remediation. Scanner FixedVersion is one
input, not the final authority. Retain all original findings and source/binary
identities; reconcile vendor advisories, upstream ranges, signed repository
metadata, and aliases without automatically suppressing findings.

1. Discover exact image digest, distro/release, architecture, installed source
   and binary package versions, and approved repository provenance.
2. Look for already-built signed packages in the same release's stable,
   security and approved updates repositories. Official same-release backports
   may be considered only if explicitly allowed and risk-reviewed; never
   automatically increase the entire repository priority.
3. Verify security coverage of the exact candidate, not just a higher version.
   Missing or conflicting evidence is unresolved. Simulate the full transaction;
   reject removal, downgrade, unapproved dependency additions, held-package
   changes, source/provenance ambiguity, and cross-release binaries.
4. Use the existing package-preserving engine/Copa where supported and
   validated. Apply to a separate immutable candidate, retain original and
   compare exact inventories, runtime config, ABI where relevant, independent
   fresh scans and workload tests. Do not publish on missing validation.
5. Where no eligible binary exists, report SOURCE_FIX_ONLY,
   NO_APPROVED_BINARY_AVAILABLE, or REVIEW_REQUIRED as applicable. Recommend
   vendor update or owner-controlled application/base-image rebuild as a
   separate workflow; AppSec does not build custom packages or silently rebase.
   EOL and unsupported images require explicit escalation.

## Fleet implementation priorities (design, not implemented)

- Generic normalized candidate/evidence schema shared by distro adapters;
  no package-specific production adapters. curl adapter is a research fixture.
- Shared vendor and repository snapshots with freshness, provenance and bounded
  retention; strict approved mirror priority; single-flight refresh; no
  per-finding live requests. Cache candidate facts by ecosystem, distro,
  release, architecture, package/source version, snapshot and policy. Do not
  reuse dependency or compatibility decisions solely by package name.
- Deduplicate scans by immutable image/platform and scanner/DB/config scope;
  tenant authorization must still be enforced. Share verified blobs by digest,
  never credentials or private results across unauthorized tenants.
- Dependency plans and validation remain image-specific. Bounded worker
  concurrency, disk quotas, timeouts, cancellation, retries and cleanup.
- Pre-start policy selects permissible changes; no mid-run decisions. Preserve
  unsupported and unresolved findings in reports. Automatic promotion is off
  until end-to-end verification is implemented and independently tested.
- Measure cold/warm scan time, cache hit rates, fix coverage, risk regressions,
  failure rates and storage on a representative image cohort before a fleet
  rollout. Do not extrapolate throughput or remediation success from nginx.

## Research result and boundary

Nginx baseline: 452 scanner findings without FixedVersion. Debian tracker
reports newer-release fixes for 292 occurrences; curl upstream review of
8.23.0 has 78 remediation leads (39 CVEs) and no affected versions in the
239-advisory snapshot. No compatible signed Trixie 8.23.0 binary was verified.
Official Trixie curl 8.21.0 backport simulated with 3 upgrades and 2 additions,
no removals, but upstream review found six new exposure leads; not an
automatic candidate. Source build-dependency simulation succeeded with
177 new build dependencies, two upgrades and zero removals. No source was
compiled and no curl remediation was verified. Close custom-build research;
do not equate source availability with installable fixes.

Next deliverable: generic read-only repository candidate catalog and routing
with exact binary provenance and security evidence. Then signed transactions
and representative multi-image verification. No claim of production readiness.
