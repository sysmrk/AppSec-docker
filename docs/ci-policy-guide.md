# CI/CD و Policy Gate

این داکیومنت نشان می‌دهد چطور AppSec Image Pipeline را در CI/CD استفاده کنید و با policy جلوی ادامه pipeline را بگیرید.

## رفتار اصلی policy

در اجرای پیش‌فرض Policy روی اسکن اولیه اجرا می‌شود و هیچ Patch یا Push انجام نمی‌شود. در حالت پیشرفته `--patch`، Policy روی اسکن Image اصلاح‌شده اجرا می‌شود.

مقادیر پیش‌فرض:

```env
POLICY_MAX_CRITICAL=0
POLICY_MAX_HIGH=0
POLICY_MAX_MEDIUM=999999
POLICY_MAX_LOW=999999
```

اگر تعداد CVEهای Critical یا High در اسکن نهایی از حد مجاز بیشتر باشد، Pipeline با وضعیت `policy_failed` پایان می‌یابد.

## اجرای ساده در CI

```bash
./scripts/appsecctl.sh ci image "$IMAGE_REF"
```

این command وقتی policy پاس شود exit code برابر `0` می‌دهد و وقتی policy fail شود یا اجرای pipeline خطا بخورد exit code غیر صفر می‌دهد. همین رفتار برای متوقف کردن pipeline کافی است.

مثال:

```bash
IMAGE_REF="alpine:3.19"
./scripts/appsecctl.sh ci image "${IMAGE_REF}"
```

## GitLab CI

```yaml
stages:
  - security

image_security:
  stage: security
  script:
    - docker compose -f docker-compose.yaml up -d postgres
    - ./scripts/appsecctl.sh migrate
    - ./scripts/appsecctl.sh ci image "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA"
  rules:
    - if: $CI_COMMIT_BRANCH
```

اگر command آخر fail شود، job و کل stage fail می‌شود.

## GitHub Actions

```yaml
name: image-security

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan-image:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Start AppSec services
        run: |
          docker compose -f docker-compose.yaml up -d postgres
          ./scripts/appsecctl.sh migrate
      - name: Run policy gate
        run: ./scripts/appsecctl.sh ci image "alpine:3.19"
```

## Jenkins Pipeline

```groovy
pipeline {
  agent any
  stages {
    stage('Image Security') {
      steps {
        sh 'docker compose -f docker-compose.yaml up -d postgres'
        sh './scripts/appsecctl.sh migrate'
        sh './scripts/appsecctl.sh ci image "$IMAGE_REF"'
      }
    }
  }
}
```

## استفاده async از API در CI

اگر می‌خواهید job را در platform مشترک ثبت کنید:

```bash
response="$(
  curl -sS -X POST http://127.0.0.1:8080/appsec-api/pipelines \
    -H "X-API-Key: ${APPSEC_API_KEY}" \
    -H 'Content-Type: application/json' \
    -d "{\"image\":\"${IMAGE_REF}\"}"
)"

job_id="$(printf '%s' "$response" | jq -r '.job_id')"
```

بعد polling کنید تا job تمام شود:

```bash
while true; do
  jobs="$(curl -sS -H "X-API-Key: ${APPSEC_API_KEY}" http://127.0.0.1:8080/appsec-api/jobs)"
  status="$(printf '%s' "$jobs" | jq -r --arg id "$job_id" '.[] | select(.id == $id) | .status')"
  pipeline_id="$(printf '%s' "$jobs" | jq -r --arg id "$job_id" '.[] | select(.id == $id) | .pipeline_id // empty')"

  case "$status" in
    success|failed|canceled) break ;;
    *) sleep 10 ;;
  esac
done

summary="$(curl -sS -H "X-API-Key: ${APPSEC_API_KEY}" "http://127.0.0.1:8080/appsec-api/pipelines/${pipeline_id}")"
pipeline_status="$(printf '%s' "$summary" | jq -r '.pipeline.status')"

test "$pipeline_status" = "success"
```

## تنظیم policy با API

Policy عمومی:

```bash
curl -X POST http://127.0.0.1:8080/appsec-api/api/policies \
  -H "X-API-Key: ${APPSEC_API_KEY}" \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"default",
    "rules":{
      "max_critical":0,
      "max_high":0,
      "max_medium":20,
      "max_low":100
    }
  }'
```

Policy مخصوص project:

```bash
curl -X POST http://127.0.0.1:8080/appsec-api/api/policies \
  -H "X-API-Key: ${APPSEC_API_KEY}" \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"payment-service-strict",
    "project_id":"<project-id>",
    "rules":{
      "max_critical":0,
      "max_high":0,
      "max_medium":5,
      "max_low":50
    }
  }'
```

## پیشنهاد برای production

- برای branchهای feature فقط `CRITICAL` و `HIGH` را gate کنید.
- برای release branch مقدار `MEDIUM` را هم محدود کنید.
- برای imageهای base و public policy سخت‌گیرانه‌تر بگذارید.
- برای موارد پذیرفته‌شده، accepted risk با owner و تاریخ انقضا ثبت کنید.
- خروجی HTML تجمیعی را به عنوان artifact همان CI job ذخیره کنید.
- اگر platform مرکزی دارید، CI فقط job ثبت کند و نتیجه را poll کند؛ اجرای Copa و Trivy روی runner مشترک CI انجام نشود.


### Secret scanning: fail closed

`./scripts/appsecctl.sh ci security secrets https://github.com/example/repo.git` returns a non-zero exit code if the security job is not `success`, OR if high findings exceed `CI_MAX_HIGH`. This prevents an unsuccessful scanner run from reporting a green CI gate. Repo HTTPS hostnames must be allowed by `SECURITY_ALLOWED_GIT_HOSTS`.


## Optional patch mode in CI

Use `./scripts/appsecctl.sh ci image "$IMAGE_REF" --patch` **only** when BuildKit is running under the `patch` profile, the registry is configured and the write action is explicitly approved. Ordinary CI should remain scan-only to avoid an unexpected registry push.


## Manual approval vs CI automation

Normal CI remains scan-only. The Control Center's guided workflow uses two separate approvals: first local patch preparation/scan, then publishing the policy-passed image to an explicitly approved Registry. The legacy advanced CLI `--patch` can still use a one-shot Patch+Push; only trusted automation operators should use it. Configure isolated executors and scoped credentials, review final policy and sign/promote images through approved enterprise controls.
