# AppSec API Guide

این راهنمای REST API برای Automation و CI/CD است؛ کاربران عادی می‌توانند از رابط وب [AppSec Control Center](user-guide.md) در آدرس `http://127.0.0.1:8080` استفاده کنند.

## آدرس و احراز هویت

وقتی platform پشت nginx بالا باشد، آدرس API این است:

```text
http://127.0.0.1:8080/appsec-api
```

برای بیشتر endpointها از API key استفاده کنید:

```http
X-API-Key: YOUR_API_KEY
```

در محیط واقعی مقدار `APPSEC_ADMIN_API_KEY` را در `.env` تغییر دهید.

## Health و Metrics

```bash
curl http://127.0.0.1:8080/appsec-api/health
curl http://127.0.0.1:8080/appsec-api/metrics
```

## اجرای scan و patch image

ثبت job در صف:

```bash
curl -X POST http://127.0.0.1:8080/appsec-api/pipelines \
  -H 'X-API-Key: YOUR_API_KEY' \
  -H 'Content-Type: application/json' \
  -d '{"image":"registry.example.com/team/api:1.4.0","priority":100,"mode":"scan"}'
```

دیدن jobها:

```bash
curl -H 'X-API-Key: YOUR_API_KEY' \
  http://127.0.0.1:8080/appsec-api/jobs
```

دیدن نتیجه یک pipeline:

```bash
curl -H 'X-API-Key: YOUR_API_KEY' \
  http://127.0.0.1:8080/appsec-api/pipelines/<pipeline-id>
```

متوقف کردن jobهایی که هنوز `queued` هستند:

```bash
curl -X POST \
  -H 'X-API-Key: YOUR_API_KEY' \
  http://127.0.0.1:8080/appsec-api/jobs/<job-id>/stop
```

حذف jobهایی که هنوز `queued` هستند:

```bash
curl -X DELETE \
  -H 'X-API-Key: YOUR_API_KEY' \
  http://127.0.0.1:8080/appsec-api/jobs/<job-id>
```

## گزارش تجمیعی و دانلود خروجی

ساخت گزارش HTML تجمیعی برای pipeline:

```bash
curl -X POST \
  -H 'X-API-Key: YOUR_API_KEY' \
  http://127.0.0.1:8080/appsec-api/api/pipelines/<pipeline-id>/reports/html
```

اگر pipeline هنوز `running` باشد، API با `409 Conflict` جواب می‌دهد. گزارش نهایی فقط برای وضعیت‌های `success`، `policy_failed` و `failed` ساخته می‌شود.

این گزارش یک فایل واحد است و بعد از کامل شدن مراحل pipeline داده‌ها را به شکل جدول نمایش می‌دهد:

- خلاصه pipeline
- metadata ایمیج شامل tag/version، digest/hash، image id، size، OS و architecture
- مراحل scan
- اجرای Copa و image patch شده
- نتیجه policy
- تعداد fixed، remaining و introduced
- درصد کاهش آسیب‌پذیری‌ها بعد از Copa
- جدول vulnerabilityهای fixed
- جدول vulnerabilityهای remaining
- جدول vulnerabilityهای introduced
- جدول همه vulnerabilityها به تفکیک scan همراه severity، CVSS score، type/class، title، description و URL
- artifactهای تولید شده مثل SBOM

لیست گزارش‌های pipeline:

```bash
curl -H 'X-API-Key: YOUR_API_KEY' \
  http://127.0.0.1:8080/appsec-api/api/pipelines/<pipeline-id>/reports
```

دانلود report:

```bash
curl -L \
  -H 'X-API-Key: YOUR_API_KEY' \
  -o report.html \
  http://127.0.0.1:8080/appsec-api/api/reports/<report-id>/download
```

همین گزارش در Control Center و داشبورد Metabase نیز قابل مشاهده است.

نکته امنیتی: همه دانلودها **همیشه نیاز به احراز هویت دارند**؛ شناسه UUID مجوز دسترسی محسوب نمی‌شود. مقدار قدیمی `DOWNLOADS_REQUIRE_AUTH=false` دیگر احراز هویت را خاموش نمی‌کند. برای دریافت گزارش از `curl` با `X-API-Key` استفاده کنید یا ابتدا Session معتبر API بسازید. لینک مستقیم دانلود بدون Session معتبر API یا API Key مجاز کار نمی‌کند. دسترسی به منابع Project-scoped باید با عضویت در همان Project سازگار باشد؛ منابع بدون Project داده‌های Shared هستند.

## Secret scanning

ثبت job برای secret scan:

```bash
curl -X POST http://127.0.0.1:8080/appsec-api/api/security-jobs \
  -H 'X-API-Key: YOUR_API_KEY' \
  -H 'Content-Type: application/json' \
  -d '{"kind":"secrets","target":"https://github.com/example/project.git","profile":"quick"}'
```

دیدن نتیجه:

```bash
curl -H 'X-API-Key: YOUR_API_KEY' \
  http://127.0.0.1:8080/appsec-api/api/security-jobs/<job-id>
```

ساخت SARIF:

```bash
curl -X POST \
  -H 'X-API-Key: YOUR_API_KEY' \
  http://127.0.0.1:8080/appsec-api/api/security-jobs/<job-id>/reports/sarif
```

## Policy

تعریف policy عمومی:

```bash
curl -X POST http://127.0.0.1:8080/appsec-api/api/policies \
  -H 'X-API-Key: YOUR_API_KEY' \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"default-strict",
    "rules":{
      "max_critical":0,
      "max_high":0,
      "max_medium":999999,
      "max_low":999999
    }
  }'
```

دیدن policyها:

```bash
curl -H 'X-API-Key: YOUR_API_KEY' \
  http://127.0.0.1:8080/appsec-api/api/policies
```

## نکات عملیاتی

- برای automation بهتر است همیشه `job_id` و بعد از پایان `pipeline_id` را ذخیره کنید.
- برای اجرای همزمان تعداد زیاد image، priority را جدی بگیرید؛ عدد کمتر زودتر پردازش می‌شود.
- لینک‌های دانلود اگر S3/MinIO فعال باشد می‌توانند به presigned URL تبدیل شوند.
- برای محیط سازمانی API را پشت reverse proxy دارای TLS، rate limit و auth خارجی قرار دهید.
- برای گزارش‌گیری مدیریتی، Metabase را منبع اصلی مشاهده کنید و API را برای orchestration نگه دارید.

## چند ایده خفن برای استفاده

- یک bot در GitLab/GitHub بسازید که با هر merge request ایمیج branch را scan کند و نتیجه Metabase را کامنت کند.
- nightly job بسازید که 100 ایمیج مهم سازمان را queue کند و صبح فقط diff نسبت به دیروز دیده شود.
- برای تیم‌ها policy متفاوت تعریف کنید؛ مثلا imageهای اینترنتی strict و imageهای داخلی با accepted risk کنترل‌شده.
- خروجی SBOM را به inventory سازمان وصل کنید تا بفهمید کدام package آسیب‌پذیر در چند image تکرار شده است.
- بعد از patch موفق، image جدید را با tag استاندارد به Harbor بفرستید و deploymentها فقط از namespace امن pull کنند.
- برای incident response، با CVE جدید در API/Metabase سرچ کنید و سریع بفهمید کدام imageها آلوده‌اند.


## تغییرات امنیتی API

- Endpointهای `/api/dashboard`، `/api/history`، `/api/teams` و `/api/audit-logs` فقط برای `admin` هستند تا تجمیع داده‌های Projectهای مختلف برای Viewer/Operator نمایش داده نشود.
- `GET /api/policies` بدون `project_id` فقط Admin؛ کاربران دیگر باید `project_id` مجاز خود را مشخص کنند.
- اسکن Source فقط روی `https://` و hostnameهای `SECURITY_ALLOWED_GIT_HOSTS` پذیرفته می‌شود (پیش‌فرض `github.com,gitlab.com`). URL دارای Credential یا Query مجاز نیست؛ Git Redirect غیرفعال است.
- فیلد `expires_at` برای Accept Risk اجباری است و باید ISO8601 آینده و دارای timezone باشد، مثال: `2027-01-01T00:00:00Z`.
- Session cookie در HTTPS با `APPSEC_SESSION_COOKIE_SECURE=true` امن می‌شود؛ برای توسعه local HTTP می‌توان false گذاشت.
- Secretهای کشف‌شده دیگر در فیلدهای Match/Secret/Line، Evidence و Metadata بازگردانده نمی‌شوند. برای پاک‌سازی تاریخچه نیاز به migration و حذف گزارش‌های ذخیره‌شده قبلی است.

## اتصال AI با MCP

API فعلی همان API معمول FastAPI است. MCP یک سرویس مستقل و اختیاری از پروفایل `mcp` است. تنظیم و آموزش اتصال Claude Desktop، MCP Inspector و AIهای remote در [mcp.md](mcp.md) آمده است.


## Scan-only default and explicit patching

New `POST /appsec-api/pipelines` requests default to `mode=scan`: Trivy, SBOM, policy and report, with **no automatic patch or push**. Advanced patch requests require a running privileged patch executor (`./appsec start --patching`), approved registry credentials, and `confirm_patch=true`:

```bash
curl -X POST http://127.0.0.1:8080/appsec-api/pipelines \
  -H "X-API-Key: ${APPSEC_API_KEY}" \
  -H 'Content-Type: application/json' \
  -d '{"image":"registry.example.com/team/api:1.4.0","mode":"patch","confirm_patch":true}'
```

## Control Center read endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /appsec-api/api/ui/overview` | Project-filtered summary, recent runs and jobs |
| `GET /appsec-api/api/ui/pipelines/{id}` | Compact pipeline details without Trivy raw JSON |
| `GET /appsec-api/api/ui/scans/{id}/vulnerabilities` | CVEs, severity filter, up to 200 records |
| `GET /appsec-api/api/ui/security-jobs/{id}` | Redacted Gitleaks findings |
| `GET /appsec-api/api/ui/capabilities` | Patch functionality status |

All endpoints require a valid AppSec session or API Key. UI lives at `/`, Metabase at `http://127.0.0.1:3001`.


`GET /appsec-api/api/ui/system/health` is an **admin-only** read endpoint for queue counts and Worker/Scheduler heartbeats. It does not query Docker Socket. Old heartbeat timestamps do not necessarily mean an executor failed.


## Manual workflow endpoints (no CI/CD required)

The browser-guided workflow is supported by authenticated REST endpoints. `POST /appsec-api/api/manual-workflows` creates a **scan-only** job. `GET /appsec-api/api/manual-workflows` lists workflows accessible to the user, and `GET /appsec-api/api/manual-workflows/{id}` returns progress, scan findings and saved reports. `POST /appsec-api/api/manual-workflows/{id}/decision` accepts `{"action":"finish"}`, `{"action":"cancel"}` for queued scans, or `{"action":"approve_patch","confirm_patch":true}` followed by `{"action":"approve_publish","confirm_push":true}` only after a successful post-patch scan and final Policy. The last action requires the completed original scan, an authorized Operator/Admin, correct Project permissions and an explicitly enabled patch executor. Patch preparation and Registry publication are separate one-attempt jobs, with user identity and timestamp recorded. Metabase only displays analytics and is not an approval interface. See [Workflow](workflow.md) and [User Guide](user-guide.md).

## v0.9 manual, identity and image management API

| Method | Route (behind `/appsec-api`) | Use |
| --- | --- | --- |
| GET | `/api/images` | Search real scanned images |
| GET | `/api/images/{image_id}/history` | Actual scan history |
| GET | `/api/images/compare/scans?from_scan=...&to_scan=...` | CVE differences |
| GET | `/api/preflight/image?image=...` | Configuration checks; pull remains **unverified** |
| GET/POST | `/api/registries` | HTTPS Registry metadata / Admin-only creation |
| POST | `/api/manual-workflows` | Start scan-only guided job |
| GET | `/api/manual-workflows/{id}` | Real progress and safe diagnostics |
| POST | `/api/manual-workflows/{id}/decision` | `finish`, `cancel`, `approve_patch`, `skip_publish`, `approve_publish` |
| GET/PATCH | `/api/users/{id}` | Admin read/update account |
| POST | `/api/users/{id}/reset-password` | Reset to a temporary password |
| POST | `/api/users/{id}/rotate-api-key` | One-time API key issuance/rotation |
| POST | `/api/users/{id}/revoke-sessions` | Invalidate web sessions |
| DELETE | `/api/teams/{team_id}/members/{user_id}` | Revoke team membership |
| POST | `/api/profile/password` | Change own password |
| POST | `/api/profile/mfa/enroll` | Start encrypted TOTP setup |
| POST | `/api/profile/mfa/confirm` | Enable MFA and return recovery codes once |
| POST | `/api/profile/mfa/disable` | Disable MFA with password and OTP |

The guided `approve_patch` requires `confirm_patch=true` but **does not publish**. Only a later `approve_publish` with `confirm_push=true`, final passed Policy, registered `allow_push` Registry destination and correct role may queue Push. Registry errors and HTTP validation failures include safe `error.code`, `error.hint` and `error.request_id` details instead of leaking raw subprocess stderr.

Browser cookie-authenticated writes require `X-Requested-With: AppSec-Control-Center`. CLI automation should use a valid API key. **Metabase is analytics only**, MCP is optional read-only analytics; neither authorizes Registry writes.
