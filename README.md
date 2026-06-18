# AppSec Image Pipeline

این پروژه یک pipeline امنیتی داکری برای container imageهاست.

هدف نسخه اول:

1. یک image با Trivy اسکن شود.
2. خروجی کامل Trivy در Postgres ذخیره شود.
3. با Copa تلاش شود image بر اساس گزارش Trivy patch شود.
4. image patch شده به registry ارسال شود.
5. image جدید دوباره با Trivy اسکن شود.
6. نتیجه scan قبل و بعد با `pipeline_id` قابل ردیابی باشد.
7. diff، policy result و SBOM برای audit ذخیره شود.

## اجزای پروژه

- `postgres`: دیتابیس اصلی برای scanها، vulnerabilityها و patch runها
- `harbor`: رجیستری سازمانی متن‌باز برای نگهداری imageهای patch شده
- `buildkit`: سرویس BuildKit برای patch کردن imageها با Copa
- `appsec-runner`: ابزار پایتونی کنترل‌کننده Trivy، Copa و دیتابیس
- `api`: API ساده برای ثبت job و دیدن وضعیت pipelineها
- `nginx`: reverse proxy امن برای Grafana و API
- `worker`: پردازشگر صف jobها
- `scheduler`: زمان‌بندی scan imageهای ثبت‌شده
- `grafana`: داشبورد اصلی برای مشاهده وضعیت scan، vulnerabilityها، patchها و policyها
- `metabase`: داشبورد تحلیلی برای گزارش‌های مدیریتی، نمودارها و جستجوی داده‌ها
- `trivy`: به صورت container اجرا می‌شود
- `copa`: داخل image مربوط به `appsec-runner` نصب می‌شود
- `gitleaks`: برای پیدا کردن secretها

همه چیز با Docker Compose اجرا می‌شود و کار دستی تا جای ممکن حذف شده است.

`appsec-runner` برای اجرای Trivy و Copa از Docker socket میزبان و Docker CLI میزبان استفاده می‌کند. این یعنی روی میزبان باید دستور `docker` کار کند.

## آماده‌سازی

```bash
cp .env.example .env
make preflight
make validate
make init
```

مسیر دستی معادل:

```bash
docker-compose -f docker-compose.yaml --profile platform up -d postgres buildkit minio minio-init api nginx worker scheduler grafana metabase
./scripts/harbor.sh install
./scripts/harbor.sh login
docker-compose -f docker-compose.yaml build appsec-runner
./scripts/appsecctl.sh migrate
./scripts/setup-metabase.sh
```

در محیط توسعه، API key پیش‌فرض این است:

```text
appsec-dev-key
```

ورود پیش‌فرض API در محیط توسعه:

```text
username: admin
password: appsec-admin
```

ورود پیش‌فرض Grafana:

```text
username: admin
password: appsec-grafana
```

ورود پیش‌فرض Metabase:

```text
url: http://127.0.0.1:3001
username: admin@appsec.local
password: AppSec-Metabase-2026!
```

برای محیط واقعی مقدارهای `APPSEC_ADMIN_API_KEY`، `APPSEC_ADMIN_PASSWORD`، `GRAFANA_ADMIN_PASSWORD` و `METABASE_ADMIN_PASSWORD` را در `.env` تغییر دهید.

اگر اسکریپت executable نبود:

```bash
chmod +x scripts/*.sh
```

برای production از نمونه تنظیمات زیر شروع کنید:

```bash
cp .env.production.example .env
```

## اجرای کامل pipeline

مثال:

```bash
./scripts/appsecctl.sh run alpine:3.19
```

اگر قرار است مرحله patch هم اجرا شود، BuildKit هم باید بالا باشد:

```bash
docker-compose -f docker-compose.yaml up -d buildkit
```

این دستور همه مراحل را انجام می‌دهد:

- scan اولیه
- ذخیره گزارش در Postgres
- patch با Copa
- push به registry
- scan مجدد image patch شده
- ساخت SBOM با فرمت CycloneDX برای image اولیه و patch شده
- ساخت diff بین vulnerabilityهای قبل و بعد
- اجرای policy روی scan نهایی
- چاپ summary

Scanهای این pipeline روی vulnerabilityهای OS-level و fixable متمرکز هستند، چون Copa دقیقاً همین دسته را بهتر patch می‌کند.

Trivy برای scan به vulnerability DB نیاز دارد. به صورت پیش‌فرض از این repository استفاده می‌شود:

```env
TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2
```

اگر شبکه شما به GitHub Container Registry دسترسی ندارد، این مقدار را در `.env` به mirror داخلی یا registry مجاز خودتان تغییر دهید.

## اجرای مرحله‌ای

فقط scan:

```bash
./scripts/appsecctl.sh scan alpine:3.19
```

patch بر اساس یک scan مشخص:

```bash
./scripts/appsecctl.sh patch --scan-id <scan-id>
```

دیدن summary:

```bash
./scripts/appsecctl.sh summary --pipeline-id <pipeline-id>
```

ثبت job در صف:

```bash
./scripts/appsecctl.sh enqueue alpine:3.19
./scripts/appsecctl.sh jobs
```

ثبت زمان‌بندی:

```bash
./scripts/appsecctl.sh schedule alpine:3.19 --interval-minutes 1440
```

## اجرای Platform

برای اجرای Grafana، Metabase، API، worker و scheduler:

```bash
docker-compose -f docker-compose.yaml --profile platform up -d postgres buildkit minio minio-init api nginx worker scheduler grafana metabase
./scripts/setup-metabase.sh
```

برای اجرای نزدیک‌تر به production با workerهای جدا:

```bash
docker-compose -f docker-compose.yaml --profile production up -d postgres buildkit api nginx image-worker security-worker scheduler
```

در این حالت API به Docker socket و workspaceها دسترسی ندارد؛ فقط workerها executor هستند. ورودی اصلی وب سرویس `nginx` است، Grafana روی ریشه 8080 نمایش داده می‌شود و API پروژه زیر مسیر `/appsec-api/` قرار دارد.

Health API:

```bash
curl http://127.0.0.1:8080/appsec-api/health
```

Metrics:

```bash
curl http://127.0.0.1:8080/appsec-api/metrics
```

داشبورد Grafana:

```text
http://127.0.0.1:8080
```

Dashboard پیش‌فرض با نام `AppSec Image Security Overview` در فولدر `AppSec` provision می‌شود. API key هنوز برای automation، CI و curl قابل استفاده است.

داشبورد Metabase با نام `AppSec Security Overview` توسط اسکریپت زیر ساخته می‌شود:

```bash
./scripts/setup-metabase.sh
```

این داشبورد شامل pipeline count، vulnerability severity، درصد کاهش Copa، pipelineهای اخیر، packageهای پرریسک، policy status و لینک گزارش‌های HTML است.

راهنمای کامل API در این فایل است:

```text
docs/api-guide.md
```

راهنمای پیاده‌سازی در CI/CD و policy gate در این فایل است:

```text
docs/ci-policy-guide.md
```

ثبت pipeline از API:

```bash
curl -X POST http://127.0.0.1:8080/appsec-api/pipelines \
  -H 'X-API-Key: appsec-dev-key' \
  -H 'Content-Type: application/json' \
  -d '{"image":"alpine:3.19"}'
```

دیدن jobها:

```bash
curl -H 'X-API-Key: appsec-dev-key' http://127.0.0.1:8080/appsec-api/jobs
```

دیدن summary یک pipeline:

```bash
curl -H 'X-API-Key: appsec-dev-key' http://127.0.0.1:8080/appsec-api/pipelines/<pipeline-id>
```

## Secret Scanning

ثبت async در صف:

```bash
./scripts/appsecctl.sh security secrets https://github.com/example/project.git --async --profile quick
```

اسکن secrets:

```bash
./scripts/appsecctl.sh security secrets https://github.com/example/project.git
```

از API هم همین اسکن قابل ثبت است؛ نتیجه‌ها در Grafana دیده می‌شوند.

از API هم async اجرا می‌شود و بلافاصله `queued` برمی‌گرداند:

```bash
curl -X POST http://127.0.0.1:8080/appsec-api/api/security-jobs \
  -H 'X-API-Key: appsec-dev-key' \
  -H 'Content-Type: application/json' \
  -d '{"kind":"secrets","target":"https://github.com/example/project.git","profile":"quick"}'
```

ابزارهای استفاده‌شده متن‌باز و docker-friendly هستند:

- Gitleaks برای secrets

## CI Mode

برای استفاده مستقیم در CI/CD:

```bash
./scripts/appsecctl.sh ci image alpine:3.19
./scripts/appsecctl.sh ci security secrets https://github.com/example/project.git --profile quick
```

اگر policy image رد شود یا security job بیشتر از `CI_MAX_HIGH` finding با severity high داشته باشد، command با exit code غیر صفر تمام می‌شود.

## Reports و Export

برای ساخت گزارش تجمیعی HTML که شامل جدول‌های scan، patch، policy، fixed، remaining، introduced، metadata ایمیج و vulnerabilityهاست:

```bash
./scripts/appsecctl.sh report pipeline <pipeline-id>
```

گزارش pipeline فقط وقتی ساخته می‌شود که وضعیت آن نهایی شده باشد: `success`، `policy_failed` یا `failed`. در اجرای عادی، سیستم بعد از تمام شدن مراحل pipeline خروجی Trivy، Copa، diff و policy را جمع می‌کند و همان موقع گزارش نهایی را می‌سازد. برای pipeline با وضعیت `running` گزارش تولید نمی‌شود، چون نتیجه Copa، scan نهایی و diff هنوز کامل نیستند.

برای security job هم گزارش HTML جدا وجود دارد:

```bash
./scripts/appsecctl.sh report security_job <security-job-id>
```

برای export به SARIF فقط برای security job:

```bash
./scripts/appsecctl.sh report security_job <security-job-id> --format sarif
```

worker بعد از موفقیت security job به صورت خودکار HTML و SARIF تولید می‌کند. برای image pipeline هم HTML report تولید می‌شود.

در Grafana:

- نام image، tag/version، وضعیت pipeline، وضعیت patch، نتیجه policy و تصویر patch شده در جدول `Image Pipeline Details` دیده می‌شود.
- تعداد و شدت آسیب‌پذیری‌ها در نمودار `Vulnerabilities By Severity And Phase` نمایش داده می‌شود.
- مواردی که Copa fix کرده، باقی‌مانده‌ها و introducedها در statها، نمودار `Copa Fix Result` و جدول pipeline دیده می‌شوند.
- لیست vulnerabilityها و packageهای پرریسک در جدول‌های جدا نمایش داده می‌شود.
- لینک دانلود گزارش نهایی در جدول `Consolidated Downloadable Reports` دیده می‌شود. این فایل یک HTML واحد است و همه داده‌های اصلی را به شکل جدول قابل خواندن نشان می‌دهد.
- گزارش شامل نام image، tag/version، digest/hash، image id، حجم، OS/architecture، تعداد و شدت vulnerabilityها، نوع/class نتیجه Trivy، CVSS score، توضیحات vulnerabilityها، نتیجه Copa و درصد کاهش آسیب‌پذیری‌هاست.
- گزارش‌ها به صورت پیش‌فرض در MinIO/S3 ذخیره می‌شوند (`ARTIFACT_STORAGE=s3`). لینک دانلود به صورت presigned ساخته می‌شود. اگر MinIO لحظه‌ای در دسترس نباشد، فایل local باقی می‌ماند تا pipeline به خاطر storage fail نشود.
- برای upload داخلی از `S3_ENDPOINT_URL` و برای لینک دانلود قابل باز شدن در مرورگر از `S3_PUBLIC_ENDPOINT_URL` استفاده می‌شود.
- چون Grafana هنگام کلیک روی link نمی‌تواند `X-API-Key` ارسال کند، دانلودها به صورت پیش‌فرض با UUID غیرقابل حدس قابل دریافت هستند. اگر می‌خواهید دانلود هم auth اجباری داشته باشد، در `.env` مقدار `DOWNLOADS_REQUIRE_AUTH=true` را بگذارید؛ در این حالت لینک‌های Grafana ممکن است بدون session معتبر API باز نشوند.

از API هم می‌توانید همان گزارش تجمیعی را دانلود کنید:

```bash
curl -L -H 'X-API-Key: appsec-dev-key' \
  -o report.html \
  http://127.0.0.1:8080/appsec-api/api/reports/<report-id>/download
```

## False Positive و Accepted Risk

برای accepted risk از API استفاده کنید. هر accept شامل reason، owner و audit log است:

```bash
curl -X POST http://127.0.0.1:8080/appsec-api/api/security-findings/<finding-id>/accept \
  -H 'X-API-Key: appsec-dev-key' \
  -H 'Content-Type: application/json' \
  -d '{"reason":"false positive in test fixture","owner":"appsec"}'
```

## Notification و Retention

اگر `NOTIFY_WEBHOOK_URL` تنظیم شود، worker بعد از موفقیت pipeline یا security job payload JSON ارسال می‌کند.

پاکسازی رکوردهای قدیمی:

```bash
./scripts/appsecctl.sh cleanup --days 30
```

## History، Search، Users و Logs

Grafana dashboard این بخش‌ها را دارد:

- summary statها برای pipelineها، vulnerabilityها، fixed، remaining و introduced
- نمودار وضعیت pipelineها در زمان
- نمودار شدت آسیب‌پذیری‌ها بر اساس scan اولیه و scan بعد از patch
- جدول imageها، version/tag، وضعیت pipeline و تصویر patch شده
- نمودار و جدول نتیجه fixهای Copa
- وضعیت patch و policy
- جدول vulnerabilityها و packageهای پرتکرار

APIهای جدید با header زیر کار می‌کنند:

```http
X-API-Key: appsec-dev-key
```

اگر TLS را پشت load balancer یا reverse proxy بیرونی فعال کردید، nginx همین مسیر را بدون اجبار SSL داخلی پشتیبانی می‌کند.

## Trivy DB Update

آپدیت دستی cache دیتابیس Trivy:

```bash
./scripts/update-trivy-db.sh
```

اجرای watch mode برای آپدیت دوره‌ای، مثلا هر 6 ساعت:

```bash
TRIVY_DB_UPDATE_INTERVAL_SECONDS=21600 ./scripts/update-trivy-db.sh --watch
```

یا با Docker Compose profile:

```bash
docker-compose -f docker-compose.yaml --profile maintenance up -d trivy-db-updater
```

اگر در شبکه سازمانی mirror دارید، مقدار زیر را در `.env` تنظیم کنید:

```env
TRIVY_DB_REPOSITORY=registry.example.com/security/trivy-db:2
```

## Stop و Down

پایین آوردن سرویس‌های پروژه:

```bash
./scripts/down.sh
```

پایین آوردن پروژه و Harbor:

```bash
./scripts/down.sh --harbor
```

حذف کامل همراه volumeها، شامل دیتابیس، گزارش‌ها و cacheها:

```bash
./scripts/down.sh --volumes --harbor
```

## Policy

به صورت پیش‌فرض scan نهایی نباید `critical` یا `high` داشته باشد:

```env
POLICY_MAX_CRITICAL=0
POLICY_MAX_HIGH=0
POLICY_MAX_MEDIUM=999999
POLICY_MAX_LOW=999999
```

اگر policy پاس نشود، pipeline با status برابر `policy_failed` تمام می‌شود، ولی گزارش‌ها و image patch شده همچنان برای بررسی باقی می‌مانند.

## Diff و SBOM

بعد از scan نهایی، سیستم vulnerabilityهای scan اولیه و patch شده را مقایسه می‌کند:

- `fixed`: مواردی که بعد از patch حذف شده‌اند
- `remaining`: مواردی که هنوز مانده‌اند
- `introduced`: موارد جدیدی که بعد از patch دیده شده‌اند

برای هر scan اصلی pipeline هم SBOM با فرمت CycloneDX JSON در volume گزارش‌ها ذخیره و مسیر آن در جدول `artifacts` ثبت می‌شود.

## Harbor Registry

به صورت پیش‌فرض خروجی Copa به Harbor لوکال push می‌شود:

```text
localhost:8081/library/appsec-patched
```

Harbor با installer رسمی خودش و Docker Compose تولیدشده توسط همان installer اجرا می‌شود:

```bash
./scripts/harbor.sh install
./scripts/harbor.sh login
./scripts/harbor.sh status
```

معادل Makefile:

```bash
make harbor-install
make harbor-login
make harbor-status
```

آدرس UI:

```text
http://localhost:8081
```

یوزر پیش‌فرض Harbor:

```text
admin / Harbor12345
```

برای محیط واقعی مقدار `HARBOR_ADMIN_PASSWORD` را عوض کنید. چون push توسط Docker daemon میزبان انجام می‌شود، `./scripts/harbor.sh login` روی میزبان لازم است.

اگر Harbor یا registry شخصی دارید، مقدارهای زیر را در `.env` تغییر دهید:

```env
REGISTRY_HOST=harbor.example.com
PATCHED_REPOSITORY=security/appsec-patched
```

اگر registry شما authentication لازم دارد، ابتدا Docker daemon میزبان را login کنید:

```bash
docker login harbor.example.com
```

چون runner از Docker socket میزبان استفاده می‌کند، credentialهای Docker میزبان برای push استفاده می‌شوند.

## جلوگیری از قاطی شدن scanها

برای هر اجرای کامل:

- یک `pipeline_id` ساخته می‌شود.
- برای scan اولیه یک `scan_id` جدا ساخته می‌شود.
- برای patch یک `patch_id` جدا ساخته می‌شود.
- برای scan نهایی یک `scan_id` جدا ساخته می‌شود.
- jobهای صف هم `job_id` جدا دارند و به `pipeline_id` وصل می‌شوند.

این یعنی حتی اگر روزی ۱۰۰ image پردازش شود، هر خروجی به run خودش وصل است.

## ساختار مهم فایل‌ها

```text
docker-compose.yaml
.env.example
db/schema.sql
runner/
scripts/appsecctl.sh
docs/
```

## Queue Control

از API، jobهایی که هنوز `queued` هستند را می‌توان کنترل کرد:

- `Stop`: وضعیت job را `canceled` می‌کند و برای audit/history نگه می‌دارد.
- `Delete`: job را از queue حذف می‌کند.

برای جلوگیری از خراب شدن state، jobهای `running` از API حذف یا stop نمی‌شوند.

## محدودیت نسخه اول

- Harbor یک stack چندسرویسی رسمی دارد؛ برای همین با `scripts/harbor.sh` و compose تولیدشده توسط installer خود Harbor مدیریت می‌شود.
- Copa ممکن است همه vulnerabilityها را patch نکند؛ فقط مواردی را patch می‌کند که برای base image و package manager قابل اصلاح باشند.
- Copa برای patch از BuildKit استفاده می‌کند؛ به همین دلیل سرویس `buildkit` کنار پروژه بالا می‌آید.
- نسخه Copa هنگام build شدن runner نصب می‌شود و از `.env` قابل تغییر است.

## مستندات بیشتر

- [Architecture](docs/architecture.md)
- [Database](docs/database.md)
- [Workflow](docs/workflow.md)
- [Registry](docs/registry.md)
- [Production Roadmap](docs/production-roadmap.md)
- [Operations Runbook](docs/operations-runbook.md)
- [Enterprise Features](docs/enterprise-features.md)
