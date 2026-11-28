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


## Opt-in UI pilot (implementation)

Set APPSEC_V4_FLEET_TEST=true before running ./appsec start (same flag
for API and worker). The host buildx plugin is mounted read-only through
the existing overlay; configure approved mirrors in Settings. Use trusted
local Debian 12/13 linux/amd64 root-default images without declared
volumes, select automatic patch and local output. The original scan
persists Debian tracker evidence (private worker-local six-hour cache)
and reports the actual signed stable/security/updates transaction plan.
The engine checks all installed packages, applies only exact existing
package upgrades, and rescans via the existing pipeline. No custom build
of packages, no removal, no cross-suite binaries, no new dependencies,
no registry publication. The application image itself is built with the
verified binary archives. Unsupported targets explicitly produce no
candidate, not a legacy mutation fallback. Vendor unavailability is
reported rather than treated as no fix. No approved official-backports
automation, shared multi-worker cache, Grype integration or full workload
validation yet; not production-ready. The existing legacy path remains
when the pilot flag is off.


### Vendor snapshot availability in restricted networks

The pilot overlay exposes fix-discovery-cache as a read-only public vendor
snapshot directory. A valid Debian Tracker JSON with file mtime under six
hours is preferred; otherwise use a fresh persistent worker cache or
download via verified HTTPS. Host-supplied data is labeled
operator_host_snapshot; SHA256 records the consumed bytes, not independent
authentication or upstream publication time. No stale fallback.
Workers on one Docker host coordinate refresh using the existing
optimization-data volume and a file lock; no multi-host cache yet.

On a host with Debian Tracker connectivity, refresh atomically:

    mkdir -p fix-discovery-cache
    curl --disable --fail --silent --show-error --proto '=https' \
      --connect-timeout 15 --max-time 180 --max-filesize 134217728 \
      https://security-tracker.debian.org/tracker/data/json \
      -o fix-discovery-cache/debian-tracker.json.part &&
    mv fix-discovery-cache/debian-tracker.json.part fix-discovery-cache/debian-tracker.json

This snapshot affects advisory discovery and reporting only. It does not
enable additional repositories, change the APT candidate or promise more
remediation. Official backports and approved vendor binaries require a
separate candidate-selection/risk-validation implementation.


### Official Backports candidate discovery in the UI pilot

After the stable plan, the worker checks installed binaries against the selected
official mirror's signed same-release Backports metadata, even when the stable
transaction is empty. The disposable probe uses only stable, updates, security
and Backports sources; no testing/unstable binaries or global pin increase.
Highest newer Backports version, source version, archive hash and filename are
recorded; exact-version dependency simulations are grouped by installed source.
Bounds: 2,000 packages, 256 binary candidates and 24 simulations. Foreign
architectures are unsupported. Optional fresh host curl feed identifies
upstream regression leads. Newer-release thresholds are not binary fix proof.

Backports decisions are REVIEW_REQUIRED. No Backports archive is downloaded
or installed. Stable mutation remains unchanged. UI and HTML show candidates,
dependency outcomes and security evidence. Generic exact-candidate advisory
verification, external approved vendor/internal repositories and automated
Backports selection remain pending. No higher patch count is promised.


### Independent scanner UI pilot

Set APPSEC_V4_INDEPENDENT_SCAN=true together with APPSEC_V4_FLEET_TEST=true.
Preload trusted Syft and Grype images (APPSEC_SYFT_IMAGE and APPSEC_GRYPE_IMAGE),
and refresh the existing host grype-cache with the approved Grype binary
before starting jobs. Do not update that cache while scans are running.
The overlay binds only the project scanner working directory and DB cache,
and scanner containers receive only the per-job input directory and read-only
Grype database. No socket, egress, implicit pull, or DB update. Raw Syft and
Grype JSON are separate artifacts; results compare only matching scanner image
IDs and database hashes, not mixed scanner counts. The engine verifies the
single archive config and layer identity; differing scanner IDs are only
accepted if exactly bound to that config. This is optional evidence, not yet
an automatic remediation selector. The current local-only publication block
remains. Max image inspect size 1 GiB, archive 2 GiB; existing bounded worker
capture may reject larger JSON. Read-only cache compatibility must be tested
on the actual Grype release. No vendor/internal repository configuration or
automatic Backports installation is added by this change.
