# Production Roadmap

این سند ۱۵ محور بلوغ سازمانی پروژه را به فازهای قابل اجرا تقسیم می‌کند.

## Phase 1 - Production Foundation

هدف: کم کردن ریسک‌های فوری و ساختن پایه عملیات.

- جدا کردن API از Docker socket و executorها
- workerهای تخصصی برای image و security
- structured JSON logging با `event`, `request_id`, `job_id`
- metrics پایه برای Prometheus
- migration framework اولیه
- مستندسازی runbook اولیه

## Phase 2 - Identity, Secrets, and Policy

هدف: قابل استفاده شدن در محیط سازمانی با کنترل دسترسی واقعی.

- OIDC/SAML با Keycloak یا Azure AD
- حذف secretها از `.env` production و اتصال به secret manager
- policy engine قابل versioning
- exception/accepted risk با expiry اجباری
- audit trail کامل برای auth و policy changes

## Phase 3 - Execution Isolation and Scale

هدف: اجرای امن‌تر و مقیاس‌پذیرتر jobها.

- executor جدا برای image و secret scanning
- resource limit و timeout per job
- worker pool قابل scale
- Kubernetes Job executor یا remote BuildKit

## Phase 4 - Artifact and Registry Governance

هدف: governance روی خروجی‌ها و imageها.

- ذخیره artifactها در S3/MinIO
- checksum و signing برای reports
- Cosign signing برای imageهای patch شده
- Harbor API integration
- tag immutability و retention policy

## Phase 5 - Enterprise Integrations

هدف: اتصال به چرخه کاری سازمان.

- GitHub/GitLab/Jenkins integration
- SARIF/GitLab security report export
- Jira/DefectDojo export
- Slack/Teams/Telegram/email notification
- backup/restore runbook و DR test

## Current Phase

فاز فعلی: **Phase 1**.

مواردی که در همین فاز باید قبل از production کامل شوند:

- حذف کامل Docker socket از API
- workerهای تخصصی
- metrics endpoint
- لاگ JSON
- migration command قابل اجرا
- runbook اولیه برای compose v1 و خطای `ContainerConfig`
