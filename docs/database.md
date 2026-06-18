# Database

Schema اصلی در [db/schema.sql](../db/schema.sql) است.

## Tables

`images`

اطلاعات imageهایی که وارد سیستم شده‌اند.

`pipeline_runs`

هر اجرای کامل scan → patch → rescan یک رکورد در این جدول دارد.

`scan_runs`

هر scan یک رکورد جدا دارد. فیلد `phase` مشخص می‌کند scan برای image اولیه بوده یا image patch شده.

`vulnerabilities`

خلاصه vulnerabilityهای استخراج‌شده از JSON خروجی Trivy.

`patch_runs`

اطلاعات اجرای Copa و image خروجی.

`pipeline_jobs`

صف پردازش pipelineها. هر job یک image، status، تعداد تلاش‌ها و در صورت موفقیت `pipeline_id` دارد.

`scan_diffs`

خلاصه مقایسه scan اولیه و scan نهایی شامل fixed، remaining و introduced.

`policy_results`

نتیجه اجرای policy روی scan نهایی همراه با ruleها و violationها.

`artifacts`

مسیر artifactهای تولیدشده مثل SBOM.

`scheduled_images`

لیست imageهایی که باید به شکل دوره‌ای وارد صف شوند.

## Raw Reports

خروجی کامل Trivy در دو جا نگه داشته می‌شود:

- فایل JSON روی volume گزارش‌ها
- ستون `raw_report` در Postgres

این کار برای audit و debug مفید است.

## IDs

برای جلوگیری از قاطی شدن اجراها، شناسه‌ها جدا نگه داشته می‌شوند:

- `job_id` برای صف
- `pipeline_id` برای اجرای کامل
- `scan_id` برای هر scan
- `patch_id` برای هر patch
- `artifact_id` برای خروجی‌هایی مثل SBOM
