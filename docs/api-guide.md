# AppSec API Guide

این داکیومنت برای استفاده دستی، automation و اتصال ابزارهای دیگر به API پروژه است.

## آدرس و احراز هویت

وقتی platform پشت nginx بالا باشد، آدرس API این است:

```text
http://127.0.0.1:8080/appsec-api
```

برای بیشتر endpointها از API key استفاده کنید:

```http
X-API-Key: appsec-dev-key
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
  -H 'X-API-Key: appsec-dev-key' \
  -H 'Content-Type: application/json' \
  -d '{"image":"alpine:3.19","priority":100}'
```

دیدن jobها:

```bash
curl -H 'X-API-Key: appsec-dev-key' \
  http://127.0.0.1:8080/appsec-api/jobs
```

دیدن نتیجه یک pipeline:

```bash
curl -H 'X-API-Key: appsec-dev-key' \
  http://127.0.0.1:8080/appsec-api/pipelines/<pipeline-id>
```

متوقف کردن jobهایی که هنوز `queued` هستند:

```bash
curl -X POST \
  -H 'X-API-Key: appsec-dev-key' \
  http://127.0.0.1:8080/appsec-api/jobs/<job-id>/stop
```

حذف jobهایی که هنوز `queued` هستند:

```bash
curl -X DELETE \
  -H 'X-API-Key: appsec-dev-key' \
  http://127.0.0.1:8080/appsec-api/jobs/<job-id>
```

## گزارش تجمیعی و دانلود خروجی

ساخت گزارش HTML تجمیعی برای pipeline:

```bash
curl -X POST \
  -H 'X-API-Key: appsec-dev-key' \
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
curl -H 'X-API-Key: appsec-dev-key' \
  http://127.0.0.1:8080/appsec-api/api/pipelines/<pipeline-id>/reports
```

دانلود report:

```bash
curl -L \
  -H 'X-API-Key: appsec-dev-key' \
  -o report.html \
  http://127.0.0.1:8080/appsec-api/api/reports/<report-id>/download
```

همین لینک در Grafana داخل جدول `Consolidated Downloadable Reports` هم نمایش داده می‌شود.

نکته امنیتی: همه دانلودها **همیشه نیاز به احراز هویت دارند**؛ شناسه UUID مجوز دسترسی محسوب نمی‌شود. مقدار قدیمی `DOWNLOADS_REQUIRE_AUTH=false` دیگر احراز هویت را خاموش نمی‌کند. برای دریافت گزارش از `curl` با `X-API-Key` استفاده کنید یا ابتدا Session معتبر API بسازید. لینک مستقیم Grafana بدون Session معتبر API کار نمی‌کند. دسترسی به منابع Project-scoped باید با عضویت در همان Project سازگار باشد؛ منابع بدون Project داده‌های Shared هستند.

## Secret scanning

ثبت job برای secret scan:

```bash
curl -X POST http://127.0.0.1:8080/appsec-api/api/security-jobs \
  -H 'X-API-Key: appsec-dev-key' \
  -H 'Content-Type: application/json' \
  -d '{"kind":"secrets","target":"https://github.com/example/project.git","profile":"quick"}'
```

دیدن نتیجه:

```bash
curl -H 'X-API-Key: appsec-dev-key' \
  http://127.0.0.1:8080/appsec-api/api/security-jobs/<job-id>
```

ساخت SARIF:

```bash
curl -X POST \
  -H 'X-API-Key: appsec-dev-key' \
  http://127.0.0.1:8080/appsec-api/api/security-jobs/<job-id>/reports/sarif
```

## Policy

تعریف policy عمومی:

```bash
curl -X POST http://127.0.0.1:8080/appsec-api/api/policies \
  -H 'X-API-Key: appsec-dev-key' \
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
curl -H 'X-API-Key: appsec-dev-key' \
  http://127.0.0.1:8080/appsec-api/api/policies
```

## نکات عملیاتی

- برای automation بهتر است همیشه `job_id` و بعد از پایان `pipeline_id` را ذخیره کنید.
- برای اجرای همزمان تعداد زیاد image، priority را جدی بگیرید؛ عدد کمتر زودتر پردازش می‌شود.
- لینک‌های دانلود اگر S3/MinIO فعال باشد می‌توانند به presigned URL تبدیل شوند.
- برای محیط سازمانی API را پشت reverse proxy دارای TLS، rate limit و auth خارجی قرار دهید.
- برای گزارش‌گیری مدیریتی، Grafana را منبع اصلی مشاهده کنید و API را برای orchestration نگه دارید.

## چند ایده خفن برای استفاده

- یک bot در GitLab/GitHub بسازید که با هر merge request ایمیج branch را scan کند و نتیجه Grafana را کامنت کند.
- nightly job بسازید که 100 ایمیج مهم سازمان را queue کند و صبح فقط diff نسبت به دیروز دیده شود.
- برای تیم‌ها policy متفاوت تعریف کنید؛ مثلا imageهای اینترنتی strict و imageهای داخلی با accepted risk کنترل‌شده.
- خروجی SBOM را به inventory سازمان وصل کنید تا بفهمید کدام package آسیب‌پذیر در چند image تکرار شده است.
- بعد از patch موفق، image جدید را با tag استاندارد به Harbor بفرستید و deploymentها فقط از namespace امن pull کنند.
- برای incident response، با CVE جدید در API/Grafana سرچ کنید و سریع بفهمید کدام imageها آلوده‌اند.


## تغییرات امنیتی API

- Endpointهای `/api/dashboard`، `/api/history`، `/api/teams` و `/api/audit-logs` فقط برای `admin` هستند تا تجمیع داده‌های Projectهای مختلف برای Viewer/Operator نمایش داده نشود.
- `GET /api/policies` بدون `project_id` فقط Admin؛ کاربران دیگر باید `project_id` مجاز خود را مشخص کنند.
- اسکن Source فقط روی `https://` و hostnameهای `SECURITY_ALLOWED_GIT_HOSTS` پذیرفته می‌شود (پیش‌فرض `github.com,gitlab.com`). URL دارای Credential یا Query مجاز نیست؛ Git Redirect غیرفعال است.
- فیلد `expires_at` برای Accept Risk اجباری است و باید ISO8601 آینده و دارای timezone باشد، مثال: `2027-01-01T00:00:00Z`.
- Session cookie در HTTPS با `APPSEC_SESSION_COOKIE_SECURE=true` امن می‌شود؛ برای توسعه local HTTP می‌توان false گذاشت.
- Secretهای کشف‌شده دیگر در فیلدهای Match/Secret/Line، Evidence و Metadata بازگردانده نمی‌شوند. برای پاک‌سازی تاریخچه نیاز به migration و حذف گزارش‌های ذخیره‌شده قبلی است.

## اتصال AI با MCP

API فعلی همان API معمول FastAPI است. MCP یک سرویس مستقل و اختیاری از پروفایل `mcp` است. تنظیم و آموزش اتصال Claude Desktop، MCP Inspector و AIهای remote در [mcp.md](mcp.md) آمده است.
