# Metabase Analytics — the single dashboard system

Grafana has been removed from AppSec. Metabase is the **only** analytics/dashboards service, running at **http://127.0.0.1:3001** on the same host as AppSec.

## Startup and authentication

```bash
./appsec setup
./appsec start
./appsec doctor
./appsec credentials
```

The `start` command initializes the Metabase database (when necessary), starts its container, waits for API readiness and calls `scripts/setup-metabase.sh`. Your `.env` must contain a unique `METABASE_ADMIN_PASSWORD` of at least 16 characters. New setups generate one. The interactive credentials command shows the AppSec and Metabase admin credentials. Metabase **does not share SSO/session/RBAC** with the Control Center.

## Dashboards available by default

| Metabase dashboard | What you see |
| --- | --- |
| **AppSec Security Overview** | Pipeline status, CVEs by severity and phase, Copa reduction, recent pipelines, top vulnerable packages, policy status and report links |
| **AppSec Manual Operations** | Workflow stages, approvals waiting for an operator, recorded decisions, scan/patch queue states and patch outcomes |
| **AppSec Vulnerability Trends** | Severity counts by scan date, most frequent CVEs by image and recent failed policy gates |

Every card is a real SQL query against the AppSec database. An empty dashboard means you have not yet performed that operation. **No demo or mock data** is seeded.

## Re-provision dashboards after upgrading

```bash
./scripts/setup-metabase.sh
```

The provisioning script searches for existing cards/dashboard names and adds missing cards without overwriting existing dashboards. Operators may customize or add cards in Metabase. This script does not execute scans, change security policy, issue approvals or patch images.

The dashboard API uses the supported `PUT /api/dashboard/{id}` route with `dashcards`, rather than the deprecated `/cards` route. Actual Metabase container and API validation in a staging environment is still required.

## Security model

Metabase analytics operate across the accessible database and **do not automatically inherit per-Project permissions** from AppSec. Restrict Metabase accounts to approved security/analytics personnel. The default Metabase database connection uses the configured AppSec PostgreSQL account; in production replace this with a dedicated **SELECT-only** role and limit table exposure. Put remote access behind TLS and centralized identity controls. Do not share administrative Metabase credentials with ordinary AppSec viewers.

The Control Center remains the place for human actions: manual scans, cancellation of queued scans, approval to patch/push, Project setup and user management. Do **not** grant mutation power through Metabase SQL.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Port 3001 unavailable | `./appsec doctor`, `./appsec logs metabase` |
| Initial setup fails | Strong `METABASE_ADMIN_PASSWORD`, `METABASE_ADMIN_EMAIL`, DNS/database reachability |
| Dashboard missing | Run `./scripts/setup-metabase.sh` and check API errors |
| No results | Verify actual scans and manual workflows ran; review PostgreSQL data |
| A chart has a SQL error | Check table/migration version with `./scripts/appsecctl.sh migrate`, run CI SQL validation |
| Need an approval | Open Control Center → **My workflows**, not Metabase |


## New Image Inventory vs Metabase

The **Images & scans** view in Control Center offers searchable individual image history and a two-scan CVE comparison. Metabase remains the **single business intelligence dashboard** for cross-image aggregated metrics, waiting approvals, policy and vulnerability trends. No Grafana and no synthetic data. Metabase is **not** a human approval system. Its independent accounts and global SQL access require a trusted network, limited users and a SELECT-only DB role before enterprise deployment.
