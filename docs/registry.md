# Harbor Registry

پروژه برای registry داخلی از Harbor استفاده می‌کند. Harbor خودش stack چندسرویسی دارد، بنابراین با installer رسمی Harbor و Docker Compose تولیدشده توسط همان installer اجرا می‌شود.

## راه‌اندازی

```bash
./scripts/harbor.sh install
./scripts/harbor.sh login
```

پیش‌فرض‌ها:

```text
UI:       http://localhost:8081
Registry: localhost:8081/library
User:     admin
Password: Harbor12345
```

برای محیط واقعی:

```bash
export HARBOR_ADMIN_PASSWORD='change-this-password'
./scripts/harbor.sh install
./scripts/harbor.sh login
```

## تنظیم مقصد imageهای patch شده

مقادیر پیش‌فرض پروژه:

```env
REGISTRY_HOST=localhost:8081
PATCHED_REPOSITORY=library/appsec-patched
```

اگر Harbor خارجی دارید:

```env
REGISTRY_HOST=harbor.example.com
PATCHED_REPOSITORY=security/appsec-patched
```

و روی میزبان Docker login کنید:

```bash
docker login harbor.example.com
```

چون push با Docker daemon میزبان انجام می‌شود، credential باید روی همان میزبان ثبت شده باشد.
