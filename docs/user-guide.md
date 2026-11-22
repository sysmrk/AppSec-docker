# AppSec Control Center — User Guide

This guide explains the actual web UI. There is **no demo mode**, mock inventory or sample vulnerability data.

## 1. First login

On the Linux/WSL host:

```bash
./appsec setup
./appsec start
./appsec doctor
```

Open `http://127.0.0.1:8080` in a browser on the same host. If AppSec is running inside WSL2, the Windows browser may be able to access the forwarded localhost address; verify your WSL networking and port mapping if it cannot.

Sign in as `admin` using the password created by setup. Retrieve it using `./appsec credentials` in a trusted interactive terminal. Existing installations retain their existing account credentials; setup never resets them.

The UI uses the existing AppSec FastAPI login/session. HTTP on localhost requires `APPSEC_SESSION_COOKIE_SECURE=false`. HTTPS deployments must enable Secure cookies.

## 2. Overview

Overview is loaded from PostgreSQL via authenticated `GET /appsec-api/api/ui/overview`; it never invents findings. It displays:

- Total pipeline runs, policy-passed runs, policy failures and execution failures visible to your account
- Recent image scans and real vulnerability severity counts
- Queue entries (queued/running/completed) with explicit scan or patch mode
- Recent repository secret scanning jobs

Click **Details** or **Results** for a run. The overview refreshes periodically while visible; **Refresh** can be used immediately.

When there are no scans, the dashboard displays empty states. This is expected.

## 3. Run an image scan (default, safe)

Choose **Scan image**. Enter an existing image reference, such as `registry.example.com/team/api:1.4.0`, and select an optional Project. If a Project is absent, the job is shared among authenticated users under the current legacy/global access model; assign a Project for tenant separation.

Click **Start image scan**. The API creates a queued `mode=scan` job. A worker performs vulnerability scanning, creates a CycloneDX SBOM, evaluates policy and writes reports. No patch or registry push occurs.

Use **Overview → Results** to view:
- Current pipeline state and failure detail (if any)
- Critical, High, Medium and Low counts
- Policy gate result, including violations
- CVE/package/version table filtered by scan phase and severity (up to 200 findings per request)
- Existing report and SBOM download links; every download requires a valid AppSec session

If no results show up, run `./appsec doctor` and `./appsec logs worker`.

## 4. Scan a repository for secrets

Choose **Scan repository** and enter an allowed HTTPS Git URL. The server enforces an exact hostname allowlist configured in `SECURITY_ALLOWED_GIT_HOSTS`; redirects and embedded Git credentials are disabled. Select a scan profile and optional Project.

The worker uses Gitleaks. API responses show severity, rule name, file location and status — **not secret contents or evidence**. Historic reports created by older versions still require manual cleanup.

## 5. Advanced: Patch and push

Patching is **disabled** unless started with `./appsec start --patching`. Do not enable on a host with sensitive production workloads: this starts privileged BuildKit and the worker has Docker daemon access.

Configure the registry and Docker login as described in [registry guide](registry.md). On **Scan image**, select **Show advanced options**, then choose **Scan + Patch + Push + Rescan**. The browser asks for explicit confirmation. The API also requires `mode=patch` and `confirm_patch=true`.

The pipeline scans the original image, attempts Copa patch, pushes a new tagged image, rescans, generates SBOM/diff, and evaluates the policy on the patched image. Patch is not guaranteed to succeed; the UI shows failures instead of inventing results.

## 6. Advanced analytics and MCP

Grafana: `http://127.0.0.1:8080/grafana/`

Metabase (optional): run `./appsec start --analytics` and visit `http://127.0.0.1:3001`.

MCP (optional): see [MCP guide](mcp.md). Connecting an AI is never necessary to use this UI.

## 7. Permission and security notes

Admin can view platform-wide data. Other users see Project-scoped runs according to membership plus legacy global/unassigned jobs. Some platform-wide administration endpoints remain admin-only. All downloads require authentication, and a valid UUID is not authorization.

For remote access, use HTTPS and an identity-aware reverse proxy. Do not publish the loopback-only HTTP endpoint directly.

## 8. Troubleshooting

| Symptom | Action |
| --- | --- |
| Page does not open | `./appsec doctor`, `./appsec status`, `./appsec logs nginx` |
| Sign-in fails | Check admin password via `./appsec credentials` (new installs) |
| Login loops over HTTPS | Verify `APPSEC_SESSION_COOKIE_SECURE=true` and TLS proxy |
| Scan remains queued | Check `./appsec logs worker` and `./appsec status` |
| No CVEs | Check job state, Trivy DB freshness, image reference and worker logs |
| Download returns 401/403 | Sign in to AppSec, or use an API key with access to the same Project |
| Patch option disabled | `./appsec start --patching`, then configure registry login |
| Metabase not available | Start explicitly with `--analytics` |
| AI/MCP not running | This is normal unless explicitly enabled |
