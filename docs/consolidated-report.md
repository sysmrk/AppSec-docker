# Single consolidated image report

Overview > Results and My workflows now show a compact before/after comparison for one pipeline. The downloadable HTML report is regenerated at a stable path after the patched scan.

The initial column describes the original scan. The after-patch column remains Pending rather than reporting false zeroes when the patched scan has not run. Color-coded bars compare Critical, High, Medium and Low on a shared scale. The Fixed, Remaining and Introduced metrics are derived from stored Trivy scan diffs. Both phase-specific vulnerability tables are expandable, with raw JSON and CycloneDX SBOM available under advanced downloads.

The configured severity thresholds are used for Recommendation only after a completed post-patch scan. A result is Recommended or Not recommended, never an automated pass/fail gate. Publication continues to require a real rescan, an authorized human decision and an approved registry destination. Errors include the failure stage, stable code, sanitized diagnostic detail and guidance.

The existing Trivy scan profile focuses on OS packages and excludes vulnerabilities without a known fix. This is not a complete application-library or unfixed-CVE inventory. Never interpret a recommendation as proof of security.
