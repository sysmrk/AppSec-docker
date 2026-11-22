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

## Current Status (2026-11-22)

بخش‌هایی از Phase 1 پیاده‌سازی شده‌اند: API مستقل از Docker socket، Workerهای جداگانه، HTTP Metrics، لاگ JSON، Alembic Migration و Runbook. Security hardening بخشی از Phase 2 نیز اعمال شده (حذف Secret خام از DB/Reportهای جدید، کنترل دسترسی Project و Expiry اجباری Risk).

**Production-ready اعلام نشده است.** موارد باز و بحرانی:

- Docker Socket روی Workerها و `privileged` برای BuildKit باید روی Executor/Host جداگانه ایزوله شوند.
- SSO/OIDC، MFA، Secret Manager و تست‌های RBAC و CSRF تکمیل شوند.
- Trivy/Gitleaks/BuildKit Imageها با Digest ثابت شوند، Image Signature بررسی شود و Egress ACL اعمال شود.
- آزمون واقعی Scan/Patch/Push، Migration، Backup/Restore و رفتار Auth در محیط تست انجام شود.
- گزارش‌های قدیمی ممکن است Secret داشته باشند؛ rotation و حذف فایل/S3/Backup خارج از Migration لازم است.
- MCP به‌صورت اختیاری اضافه شده ولی برای اتصال از Cloud به OAuth/TLS Gateway نیاز دارد؛ راهنما: `docs/mcp.md`.

پیشرفت مرحله‌ای: Foundation انجام‌شده اما هنوز Gateهای امنیتی عملیاتی مانع Production Signoff هستند. این وضعیت به‌جای ادعای نادرست Phase 1 تمام‌شده درج شده است.


## Consolidation status — November 22, 2026

**Implemented on main:** complete interactive non-CI/CD Control Center; scan-only image intake with human review; explicitly approved Patch/Push continuation with audit identity, timestamp and maximum one attempt; admin UI for users, teams, projects, membership and policies; three Metabase dashboards; Grafana fully removed; optional read-only MCP; automated `change-<SHA>` tags for every main commit.

**Still required for production signoff:** isolate Docker Socket and privileged BuildKit workers; integrate OIDC/SSO/MFA and CSRF protections; enforce Metabase read-only SQL access and independently scoped analytics users; pin/sign images; validate actual Trivy/Copa/Harbor workflows, browser E2E and staging migrations; backup/restore and HA verification. Passing CI (including PostgreSQL migrations and Metabase SQL EXPLAIN) is not an equivalent substitute for those operational tests.
