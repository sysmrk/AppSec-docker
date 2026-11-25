# REST API — v2

Base URL through Nginx: http://127.0.0.1:8080/appsec-api. Paths below are relative to that base. Use HTTPS remotely. Authenticate with X-API-Key (issued by admin) or web session cookie. Cookie-authenticated mutations require X-Requested-With: AppSec-Control-Center. Never put credentials in URLs or logs. Access is checked against role and resource/project scope; legacy unassigned resources have broader visibility than creator-private manual workflows.

```bash
BASE=http://127.0.0.1:8080/appsec-api
read -rsp 'API key: ' APPSEC_KEY; echo
curl -fsS -H "X-API-Key: $APPSEC_KEY" "$BASE/api/ui/overview"
```

## Guided workflow

```bash
curl -fsS -X POST "$BASE/api/manual-workflows" \
  -H "X-API-Key: $APPSEC_KEY" -H 'Content-Type: application/json' \
  -d '{"image":"nginx:latest"}'
```

Use returned workflow ID with GET /api/manual-workflows/{id}. Check real state and patch_eligibility before deciding. POST /api/manual-workflows/{id}/decision accepts:

| Action | Body fields / condition |
| --- | --- |
| finish | action=finish; initial scan complete |
| cancel | action=cancel; queued only |
| approve_patch | action=approve_patch, confirm_patch=true; verified fixable OS evidence |
| skip_publish | action=skip_publish; completed prepared rescan |
| approve_publish | action=approve_publish, confirm_push=true, destination=full approved image; risk_reason when not recommended |

Approval is not completion. Poll the workflow; publication is single-attempt, requires authorized destination and verified rescan. No automatic publication in POST /pipelines (mode=scan default; patch with confirm_patch=true prepares locally).

## Endpoint catalogue

| Method | Path | Purpose |
| --- | --- | --- |
| GET | /health, /metrics | Service/database health and metrics |
| POST | /pipelines | Queue image scan/local patch |
| GET | /jobs, /pipelines/{id} | Job list and pipeline detail |
| POST | /jobs/{id}/stop, /schedules | Cancel eligible job / schedule scans |
| GET | /api/manual-workflows, /api/manual-workflows/{id} | Scoped workflow state |
| GET | /api/ui/image-workflows?page=1&limit=20 | Paginated history |
| GET | /api/ui/pipelines/{id}, /api/ui/scans/{id}/vulnerabilities | Compact evidence and filtered findings |
| POST | /api/ui/pipelines/export | JSON pipeline_ids list; one HTML or ZIP |
| DELETE | /api/pipelines/{id}/history?confirm={id} | Admin-only idle pipeline purge |
| GET | /api/maintenance/image-removals | Local image cleanup status |
| POST | /api/maintenance/image-removals/retry | Retry failed local cleanup |
| POST | /api/security-jobs | kind=secrets, target HTTPS, profile, optional project_id and repo_username/repo_password |
| GET | /api/security-jobs/{id}, /api/ui/security-jobs/{id} | Redacted repository results |
| POST | /api/security-findings/{id}/accept | Accepted risk with expiry |
| POST | /api/pipelines/{id}/reports/html | Generate HTML for finished pipeline |
| POST | /api/security-jobs/{id}/reports/html, /reports/sarif (same job prefix) | Generate repository report |
| GET | /api/pipelines/{id}/reports, /api/security-jobs/{id}/reports | Report metadata |
| GET | /api/reports/{id}/download, /api/artifacts/{id}/download | Authorized downloads |
| GET | /api/images, /api/images/{id}/history | Image inventory |
| GET | /api/images/compare/scans?from_scan=...&to_scan=... | Recorded scan diff |
| GET | /api/preflight/image?image=... | Config checks, pull unverified |
| GET/POST | /api/registries, /api/image-pull-sources | Registry metadata and approved sources |
| PUT/DELETE | /api/image-pull-sources/{id} | Priority/enabled change or removal |
| GET/POST | /api/teams, /api/projects, /api/policies, /api/users | Scoped reads/admin management |
| GET | /api/policies/effective | Effective thresholds |
| GET | /api/tool-updates | Admin release state |
| POST | /api/tool-updates/check, /api/tool-updates/{tool}/apply | Queue checks/approved update |
| GET | /api/ui/system/health, /api/ui/capabilities, /ui/build-info | Runtime diagnostics (system health admin) |

Account endpoints: POST /api/auth/login and logout; GET /api/profile; POST /api/profile/password, /api/profile/mfa/enroll, confirm, disable; GET/PATCH /api/users/{id}; POST /api/users/{id}/reset-password, rotate-api-key, revoke-sessions; DELETE /api/teams/{team_id}/members/{user_id}. Admin-only global dashboard, history and audit endpoints. Consult source request models in runner/appsecctl/api.py for exact fields and limits.

Errors include sanitized diagnostics/correlation IDs; 401 unauthenticated, 403 forbidden, 409 state conflict, 422 validation failure. Never infer completed execution from a queued response or HTTP 200 alone. Keep credentials out of examples and unset APPSEC_KEY when finished.
