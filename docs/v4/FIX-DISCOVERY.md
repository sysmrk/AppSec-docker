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


## Phase 2: upstream reference discovery

Download the official tracker text database (NOTEs include upstream references).
No clone, Docker, image archive or scanner database copy is needed.

    curl --fail --show-error --silent --connect-timeout 15 --max-time 180 \
      --proto '=https' --max-filesize 134217728 \
      https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/CVE/list \
      -o fix-discovery-cache/debian-cve-list.part &&
    mv fix-discovery-cache/debian-cve-list.part fix-discovery-cache/debian-cve-list

    python3 scripts/v4-fix-research.py \
      --discovery benchmark-results/fix-discovery-01.json \
      --cve-list fix-discovery-cache/debian-cve-list \
      --output benchmark-results/fix-research-01.json

The report prioritizes Critical then High then total newer-suite finding
occurrences. All original Trivy findings remain represented. It groups source
packages and collects the highest reported source fix per newer suite using
dpkg version ordering. This is NOT proof that any binary can be installed.
NOTE URLs are unverified leads; no automatic fetching or execution is done.
Signed same-release/backports binary indexes, package identity, dependencies,
ABI, patch applicability and workload testing remain separate gates.


## Phase 3: upstream curl ranges before official backport experiments

APT on the original Trixie image resolved curl/libcurl 8.21.0-2~bpo13+1
with one further upgrade and two new dependencies, no removals. Default
APT candidate remained 8.14.1-2+deb13u7 (backports priority 100).
Do not install or autoremove yet: a newer version can introduce vulnerabilities.

    curl --fail --show-error --silent --connect-timeout 15 --max-time 90 \
      --proto '=https' --max-filesize 16777216 \
      https://curl.se/docs/vuln.json \
      -o fix-discovery-cache/curl-vuln.json.part &&
    mv fix-discovery-cache/curl-vuln.json.part fix-discovery-cache/curl-vuln.json

    python3 scripts/v4-curl-upstream.py \
      --research benchmark-results/fix-research-01.json \
      --feed fix-discovery-cache/curl-vuln.json \
      --original-upstream 8.14.1 --candidate-upstream 8.21.0 \
      --output benchmark-results/curl-upstream-01.json

Evaluate explicit upstream introduced/fixed intervals (including
reintroductions), count package occurrences and distinct CVEs separately,
and flag new candidate-only upstream exposures across the full feed.
Do not convert these results to FixedVersion or assume upstream applicability
equals Debian binary applicability. Verify exact signed backport source,
changelog and build configuration, then perform a bounded package-preserving
lab test if warranted.

Scanner lab CI: run offline scanner as invoking host UID/GID, not container
root with all capabilities dropped, so private copied cache is accessible
without broadening permissions or restoring DAC override.
