# Architecture

Pipeline فعلی چهار بخش اصلی دارد:

```text
User
  |
  v
appsecctl / API / Scheduler
  |
  +--> Postgres queue
  |
  v
worker
  |
  +--> Trivy container
  |
  +--> Postgres
  |
  +--> Copa binary
  |
  +--> BuildKit
  |
  +--> Docker Registry / Harbor
```

`appsecctl` و `worker` خودشان scanner یا patcher نیستند. نقش آن‌ها orchestration است:

- اجرای Trivy
- خواندن JSON خروجی
- ذخیره raw report و vulnerabilityها در Postgres
- ساخت SBOM
- اجرای binary مربوط به Copa با report همان scan
- استفاده از BuildKit برای ساخت لایه patch
- push image اصلاح‌شده
- اجرای scan نهایی
- ساخت diff بین scan اولیه و نهایی
- اجرای policy

## چرا Docker socket mount شده است؟

Trivy به صورت container اجرا می‌شود و Copa داخل runner نصب است. برای patch و push image، Copa و runner باید به Docker daemon میزبان دسترسی داشته باشند.

به همین دلیل `appsec-runner` به `/var/run/docker.sock` وصل می‌شود.

این دسترسی قدرتمند است و باید فقط روی سیستم قابل اعتماد استفاده شود.

## Scale روزانه

برای جلوگیری از تداخل:

- هر pipeline یک UUID دارد.
- هر scan یک UUID دارد.
- هر patch یک UUID دارد.
- reportها با timestamp و UUID ذخیره می‌شوند.

برای پردازش کنترل‌شده، جدول `pipeline_jobs` نقش queue را دارد. workerها jobها را با lock دیتابیس claim می‌کنند، بنابراین چند worker می‌توانند کنار هم اجرا شوند بدون اینکه یک job دوبار برداشته شود.

## API

سرویس `api` با FastAPI اجرا می‌شود و پشت nginx از مسیر `http://127.0.0.1:8080/appsec-api/` در دسترس است. این سرویس job ثبت می‌کند، jobها را لیست می‌کند و summary pipeline را برمی‌گرداند. رابط مشاهده عملیاتی پروژه Grafana است که روی `http://127.0.0.1:8080` نمایش داده می‌شود. برای تحلیل‌های مدیریتی و queryهای قابل تغییر، Metabase روی `http://127.0.0.1:3001` بالا می‌آید و با `scripts/setup-metabase.sh` dashboardهای اولیه‌اش ساخته می‌شوند.

## Scheduler

سرویس `scheduler` جدول `scheduled_images` را بررسی می‌کند و وقتی زمان اجرای یک image برسد، یک job جدید در صف می‌سازد.
