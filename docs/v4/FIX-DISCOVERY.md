# V4 Fix Discovery — phase 1

The earlier Trivy run had 452 blank FixedVersion findings. Blank is a scanner
observation, not proof of absence of a fix. Trivy's targeted Copa input filters
blank values; comprehensive native upgrades are separate. We do not rewrite the
raw scan or make Copa consume unverified source versions.

Use the existing reports; no Docker or DB copy required. Obtain one official
Debian Security Tracker snapshot over verified HTTPS:

    mkdir -p fix-discovery-cache
    chmod 700 fix-discovery-cache
    curl --fail --show-error --silent --connect-timeout 15 --max-time 180 \
      --proto '=https' --max-filesize 134217728 \
      https://security-tracker.debian.org/tracker/data/json \
      -o fix-discovery-cache/debian-tracker.json.part &&
    mv fix-discovery-cache/debian-tracker.json.part fix-discovery-cache/debian-tracker.json

    python3 scripts/v4-fix-discovery.py \
      --trivy-report benchmark-results/nginx-native-02/original.json \
      --tracker fix-discovery-cache/debian-tracker.json \
      --output benchmark-results/fix-discovery-01.json

The host requires Python 3.10+ and dpkg. If the official feed is unavailable,
transfer a verified snapshot from an approved network rather than disabling
TLS. Keep the exact snapshot/hash. The offline script does not authenticate
operator-provided data or assert snapshot freshness.

Every original Debian OS finding is counted, including LOW, UNKNOWN, TEMP,
missing source mappings and missing tracker entries. Source identity is based
on exact scanner package metadata; missing/ambiguous mappings require native
inventory verification in the next phase. Debian tracker uses source versions,
not necessarily binary versions. Fixed version 0 means archive source not
affected; review rather than suppress. Newer suite fixes are leads, not
installable fixes. A later snapshot cannot establish historical scanner error.

Optional Grype raw JSON is accepted only when its source target imageID
exactly matches the Trivy image; otherwise reject and use Trivy-only until
SBOM-to-report provenance is verified. Separate counts, never sum scanners.
Next phase: signed same-release APT candidate/source metadata, native dpkg
source identity, tracker notes/security commits, upstream and backport leads;
no mutation or promotion until independently validated.
