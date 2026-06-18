# Workflow

## Full Pipeline

```bash
./scripts/appsecctl.sh run alpine:3.19
```

مراحل:

1. ساخت `pipeline_id`
2. اجرای Trivy روی image اولیه
3. ذخیره report در Postgres
4. ساخت SBOM برای image اولیه
5. اجرای Copa داخل `appsec-runner` با report همان `scan_id`
6. ساخت لایه patch با BuildKit
7. push image patch شده به registry
8. scan مجدد image patch شده
9. ساخت SBOM برای image patch شده
10. ساخت diff بین scan اولیه و scan نهایی
11. اجرای policy روی scan نهایی
12. ذخیره نتیجه نهایی

## Manual Scan

```bash
./scripts/appsecctl.sh scan nginx:1.25
```

این دستور فقط scan انجام می‌دهد و patch اجرا نمی‌کند.

Trivy vulnerability DB را روی volume جدا cache می‌کند تا هر scan مجبور نباشد DB را دوباره دانلود کند.

## Manual Patch

```bash
./scripts/appsecctl.sh patch --scan-id <scan-id>
```

این دستور از گزارش scan ذخیره‌شده استفاده می‌کند.

## Queue

برای ثبت job:

```bash
./scripts/appsecctl.sh enqueue nginx:1.25
```

برای دیدن jobها:

```bash
./scripts/appsecctl.sh jobs
```

worker اولین job با status برابر `queued` را claim می‌کند. claim با `FOR UPDATE SKIP LOCKED` انجام می‌شود تا اگر چند worker بالا آمدند یک job را همزمان برندارند.

## Scheduler

برای ثبت image زمان‌بندی‌شده:

```bash
./scripts/appsecctl.sh schedule nginx:1.25 --interval-minutes 1440
```

سرویس `scheduler` به صورت دوره‌ای imageهای due را به صف اضافه می‌کند.
