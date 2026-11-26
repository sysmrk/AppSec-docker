# V4 scanner comparison — read-only lab

No removal, build, runtime execution, registry push or AppSec service required.
Syft catalogs the local image archive; Grype scans the resulting SBOM using a
separately prepared frozen DB. Both tools are Apache-2.0 upstream projects.
Use explicitly approved mirrors and verify publisher/digest before trusting the
scanner images. Image IDs are pinned when running; no scanner container may pull
or contact the network. The DB download is an explicit separate operation.

Example (replace registry paths with approved available sources):

    docker pull docker.arvancloud.ir/anchore/syft:latest
    docker pull docker.arvancloud.ir/anchore/grype:latest
    mkdir -p grype-cache
    chmod 700 grype-cache
    docker run --rm --pull=never --user 0:0 \
      -e GRYPE_DB_CACHE_DIR=/db \
      -v "$PWD/grype-cache:/db" \
      docker.arvancloud.ir/anchore/grype:latest db update

The DB endpoint is upstream Grype, not a Docker registry; use approved network
access or an upstream-supported offline DB import. Do not disable verification.
No Grype cache writer may run while comparing images. The lab requires Grype DB
age validation (72h) and hash validation.

    python3 scripts/v4-scanner-compare.py \
      --image ORIGINAL_IMAGE --image PATCHED_IMAGE \
      --syft docker.arvancloud.ir/anchore/syft:latest \
      --grype docker.arvancloud.ir/anchore/grype:latest \
      --grype-cache ./grype-cache \
      --trivy-report ./benchmark-results/nginx-native-02/original.json \
      --trivy-report ./benchmark-results/nginx-native-02/candidate-1.json \
      --output ./benchmark-results/nginx-scanners-01

The existing Trivy files are optional and must match exact image IDs and order.
The report compares exact advisory IDs only, not package equivalence or aliases.
Raw SBOM/Grype output and DB hashes are retained privately. No security
recommendation or publication permission is inferred. Grype-reported fixes
must be reconciled against signed vendor repositories before any upgrade.
