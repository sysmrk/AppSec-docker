# AppSec Workflow

## Default: scan only

The Control Center **Scan image** form and `POST /appsec-api/pipelines` default to `mode=scan`. This scans a real image, stores Trivy JSON, generates CycloneDX SBOM, runs Policy Gate and writes a final report. **It does not patch or push.**

```bash
./scripts/appsecctl.sh run registry.example.com/team/service:1.4.0
```

Worker queue mode is stored in `pipeline_jobs.mode`. Already queued pre-upgrade jobs keep their previous patch mode after migration 0007 for compatibility. New scheduled scans default to scan-only.

## Advanced: patch + rescan

**Explicit opt-in required** (privileged BuildKit, Docker registry permissions):

```bash
./appsec start --patching
./scripts/harbor.sh login  # or docker login your registry
./scripts/appsecctl.sh run registry.example.com/team/service:1.4.0 --patch
```

From the UI, enable advanced options and explicitly confirm patch/push. API requires `{"image":"...", "mode":"patch", "confirm_patch":true}` and server setting `APPSEC_PATCH_ENABLED=true`.

A full patch run performs initial scan, original SBOM, Copa patch through BuildKit, registry push, patched scan/SBOM, CVE diff, policy check and final report.

## Repository secret scanning

In the UI choose **Scan repository**, or run `./scripts/appsecctl.sh security secrets https://github.com/org/repo.git --async`. Git targets must belong to `SECURITY_ALLOWED_GIT_HOSTS` (HTTPS only). Gitleaks values are redacted before persistence.

## Queue and scheduler

```bash
./scripts/appsecctl.sh enqueue registry.example.com/team/service:1.4.0
./scripts/appsecctl.sh jobs
./scripts/appsecctl.sh schedule registry.example.com/team/service:1.4.0 --interval-minutes 1440
```

The scheduler and queue default to scan-only. Worker claim uses `FOR UPDATE SKIP LOCKED` for concurrent workers.

## Results

UI **Overview → Results** presents real pipeline and CVE data, severity filters, policy violations, optional Before/After diff, generated reports and SBOM download links. Grafana/Metabase remain available under Integrations.
