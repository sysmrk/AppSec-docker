#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


BASE_URL = os.environ.get("METABASE_URL", "http://127.0.0.1:3001").rstrip("/")
ADMIN_EMAIL = os.environ.get("METABASE_ADMIN_EMAIL", "admin@appsec.local")
ADMIN_PASSWORD = os.environ.get("METABASE_ADMIN_PASSWORD", "AppSec-Metabase-2026!")
SITE_NAME = os.environ.get("METABASE_SITE_NAME", "AppSec Analytics")
APPSEC_DB_NAME = os.environ.get("POSTGRES_DB", "appsec")
APPSEC_DB_USER = os.environ.get("POSTGRES_USER", "appsec")
APPSEC_DB_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "appsec-change-me")
APPSEC_DB_HOST = os.environ.get("METABASE_APPSEC_DB_HOST", "postgres")
APPSEC_DB_PORT = int(os.environ.get("POSTGRES_PORT", "5432"))


def request(method: str, path: str, payload: dict | None = None, token: str | None = None) -> dict | list | None:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Metabase-Session"] = token
    req = urllib.request.Request(f"{BASE_URL}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {path} failed: {exc.code} {body}") from None
    if not raw:
        return None
    return json.loads(raw.decode("utf-8"))


def wait_for_metabase() -> None:
    for _ in range(80):
        try:
            request("GET", "/api/session/properties")
            return
        except Exception:
            time.sleep(3)
    raise RuntimeError("Metabase did not become ready")


def login() -> str:
    response = request("POST", "/api/session", {"username": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    return str(response["id"])


def setup_if_needed() -> str:
    props = request("GET", "/api/session/properties")
    token = props.get("setup-token") if isinstance(props, dict) else None
    if token:
        try:
            request(
                "POST",
                "/api/setup",
                {
                    "token": token,
                    "user": {
                        "first_name": "AppSec",
                        "last_name": "Admin",
                        "email": ADMIN_EMAIL,
                        "password": ADMIN_PASSWORD,
                        "site_name": SITE_NAME,
                    },
                    "prefs": {
                        "site_name": SITE_NAME,
                        "site_locale": "en",
                        "allow_tracking": False,
                    },
                },
            )
        except RuntimeError as exc:
            if "user currently exists" not in str(exc):
                raise
    return login()


def ensure_database(session: str) -> int:
    databases = request("GET", "/api/database", token=session)
    data = databases.get("data", databases) if isinstance(databases, dict) else databases
    for item in data or []:
        if item.get("name") == "AppSec PostgreSQL":
            return int(item["id"])
    created = request(
        "POST",
        "/api/database",
        {
            "engine": "postgres",
            "name": "AppSec PostgreSQL",
            "details": {
                "host": APPSEC_DB_HOST,
                "port": APPSEC_DB_PORT,
                "dbname": APPSEC_DB_NAME,
                "user": APPSEC_DB_USER,
                "password": APPSEC_DB_PASSWORD,
                "ssl": False,
            },
            "is_full_sync": True,
            "is_on_demand": False,
            "schedules": {},
        },
        token=session,
    )
    return int(created["id"])


def search(session: str, query: str, model: str) -> dict | None:
    path = "/api/search?" + urllib.parse.urlencode({"q": query})
    results = request("GET", path, token=session)
    for item in results.get("data", results) if isinstance(results, dict) else results:
        if item.get("name") == query and item.get("model") == model:
            return item
    return None


def ensure_card(session: str, database_id: int, name: str, sql: str, display: str = "table") -> int:
    existing = search(session, name, "card")
    if existing:
        return int(existing["id"])
    card = request(
        "POST",
        "/api/card",
        {
            "name": name,
            "display": display,
            "dataset_query": {
                "type": "native",
                "database": database_id,
                "native": {"query": sql},
            },
            "visualization_settings": {},
        },
        token=session,
    )
    return int(card["id"])


def ensure_dashboard(session: str, name: str) -> int:
    existing = search(session, name, "dashboard")
    if existing:
        return int(existing["id"])
    dashboard = request(
        "POST",
        "/api/dashboard",
        {"name": name, "description": "AppSec image security overview generated by scripts/setup-metabase.py"},
        token=session,
    )
    return int(dashboard["id"])


def dashboard_card_ids(session: str, dashboard_id: int) -> set[int]:
    dashboard = request("GET", f"/api/dashboard/{dashboard_id}", token=session)
    cards = dashboard.get("dashcards") or dashboard.get("ordered_cards") or []
    result = set()
    for item in cards:
        card = item.get("card") or {}
        card_id = item.get("card_id") or card.get("id")
        if card_id:
            result.add(int(card_id))
    return result


def add_card(session: str, dashboard_id: int, card_id: int, row: int, col: int, size_x: int = 12, size_y: int = 8) -> None:
    dashboard = request("GET", f"/api/dashboard/{dashboard_id}", token=session)
    existing_cards = dashboard.get("dashcards") or dashboard.get("ordered_cards") or []
    existing_ids = set()
    cards_payload = []
    for item in existing_cards:
        existing_card = item.get("card") or {}
        existing_card_id = item.get("card_id") or existing_card.get("id")
        if not existing_card_id:
            continue
        existing_ids.add(int(existing_card_id))
        cards_payload.append(
            {
                "id": item.get("id"),
                "card_id": int(existing_card_id),
                "row": item.get("row", 0),
                "col": item.get("col", 0),
                "size_x": item.get("size_x") or item.get("sizeX") or 12,
                "size_y": item.get("size_y") or item.get("sizeY") or 8,
                "parameter_mappings": item.get("parameter_mappings") or [],
                "visualization_settings": item.get("visualization_settings") or {},
            }
        )
    if card_id in existing_ids:
        return
    cards_payload.append(
        {
            "id": -1,
            "card_id": card_id,
            "row": row,
            "col": col,
            "size_x": size_x,
            "size_y": size_y,
            "parameter_mappings": [],
            "visualization_settings": {},
        }
    )
    request(
        "PUT",
        f"/api/dashboard/{dashboard_id}/cards",
        {"cards": cards_payload},
        token=session,
    )


CARDS = [
    (
        "AppSec - Pipeline Counts",
        "SELECT status, count(*) AS total FROM pipeline_runs GROUP BY status ORDER BY total DESC;",
        "bar",
        0,
        0,
        8,
        6,
    ),
    (
        "AppSec - Vulnerabilities By Severity And Phase",
        """
        SELECT sr.phase, v.severity, count(*) AS findings
        FROM vulnerabilities v
        JOIN scan_runs sr ON sr.id = v.scan_id
        GROUP BY sr.phase, v.severity
        ORDER BY sr.phase, CASE v.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END;
        """,
        "bar",
        0,
        8,
        16,
        6,
    ),
    (
        "AppSec - Copa Reduction By Pipeline",
        """
        SELECT pr.started_at,
               pr.requested_image,
               pr.status,
               sd.fixed_count,
               sd.remaining_count,
               sd.introduced_count,
               ROUND((sd.fixed_count::numeric / NULLIF(sd.fixed_count + sd.remaining_count, 0)) * 100, 2) AS reduction_percent
        FROM scan_diffs sd
        JOIN pipeline_runs pr ON pr.id = sd.pipeline_id
        ORDER BY pr.started_at DESC
        LIMIT 100;
        """,
        "table",
        6,
        0,
        24,
        8,
    ),
    (
        "AppSec - Recent Pipelines",
        """
        SELECT pr.started_at, pr.finished_at, pr.requested_image, pr.status,
               COALESCE(os.critical_count, 0) AS original_critical,
               COALESCE(os.high_count, 0) AS original_high,
               COALESCE(ps.critical_count + ps.high_count + ps.medium_count + ps.low_count + ps.unknown_count, 0) AS patched_total
        FROM pipeline_runs pr
        LEFT JOIN LATERAL (
          SELECT * FROM scan_runs sr WHERE sr.pipeline_id = pr.id AND sr.phase = 'original' ORDER BY sr.started_at DESC LIMIT 1
        ) os ON true
        LEFT JOIN LATERAL (
          SELECT * FROM scan_runs sr WHERE sr.pipeline_id = pr.id AND sr.phase = 'patched' ORDER BY sr.started_at DESC LIMIT 1
        ) ps ON true
        ORDER BY pr.started_at DESC
        LIMIT 50;
        """,
        "table",
        14,
        0,
        24,
        8,
    ),
    (
        "AppSec - Top Vulnerable Packages",
        """
        SELECT v.pkg_name, v.severity, count(*) AS findings, max(v.fixed_version) AS latest_fixed_version
        FROM vulnerabilities v
        GROUP BY v.pkg_name, v.severity
        ORDER BY findings DESC
        LIMIT 50;
        """,
        "table",
        22,
        0,
        12,
        8,
    ),
    (
        "AppSec - Policy Status",
        "SELECT status, count(*) AS total FROM policy_results GROUP BY status ORDER BY total DESC;",
        "pie",
        22,
        12,
        12,
        8,
    ),
    (
        "AppSec - Downloadable HTML Reports",
        """
        SELECT gr.created_at,
               pr.requested_image,
               pr.status,
               gr.path,
               '/appsec-api/api/reports/' || gr.id || '/download' AS download_path
        FROM generated_reports gr
        JOIN pipeline_runs pr ON pr.id::text = gr.resource_id
        WHERE gr.resource_type = 'pipeline'
          AND gr.format = 'html'
          AND pr.status IN ('success', 'policy_failed', 'failed')
        ORDER BY gr.created_at DESC
        LIMIT 100;
        """,
        "table",
        30,
        0,
        24,
        8,
    ),
]



MANUAL_CARDS = [
    ("AppSec Manual - Workflow States", """
        SELECT CASE
          WHEN w.decision = 'finish' THEN 'completed without patch'
          WHEN w.decision = 'approve_patch' AND p.status = 'success' THEN 'completed after patch'
          WHEN w.decision = 'approve_patch' AND p.status = 'failed' THEN 'patch failed'
          WHEN w.decision = 'approve_patch' THEN 'patch processing'
          WHEN j.status = 'success' THEN 'awaiting approval'
          WHEN j.status = 'failed' THEN 'scan failed'
          ELSE j.status END AS stage, count(*) AS workflows
        FROM manual_workflows w JOIN pipeline_jobs j ON j.id = w.scan_job_id
        LEFT JOIN pipeline_jobs p ON p.id = w.patch_job_id
        GROUP BY 1 ORDER BY 2 DESC
    """, "bar", 0, 0, 12, 7),
    ("AppSec Manual - Approval Queue", """
        SELECT w.created_at, w.requested_image, u.username AS requested_by,
               j.finished_at AS scanned_at, pr.status AS policy_status,
               pr.id AS pipeline_id
        FROM manual_workflows w JOIN pipeline_jobs j ON j.id = w.scan_job_id
        JOIN users u ON u.id = w.created_by
        LEFT JOIN pipeline_runs pr ON pr.id = j.pipeline_id
        WHERE j.status = 'success' AND w.decision IS NULL
        ORDER BY j.finished_at DESC LIMIT 100
    """, "table", 0, 12, 12, 7),
    ("AppSec Manual - Decisions And Audit", """
        SELECT w.approved_at, w.requested_image, u.username AS decided_by,
               w.decision, pj.status AS patch_status, w.project_id
        FROM manual_workflows w LEFT JOIN users u ON u.id = w.approved_by
        LEFT JOIN pipeline_jobs pj ON pj.id = w.patch_job_id
        WHERE w.decision IS NOT NULL
        ORDER BY w.approved_at DESC LIMIT 100
    """, "table", 7, 0, 24, 8),
    ("AppSec Manual - Queue By Mode", """
        SELECT mode, status, count(*) AS jobs FROM pipeline_jobs
        GROUP BY mode, status ORDER BY mode, status
    """, "bar", 15, 0, 12, 7),
    ("AppSec Manual - Patch Outcomes", """
        SELECT pr.started_at, pr.requested_image, sd.fixed_count, sd.remaining_count,
               sd.introduced_count, pr.status
        FROM scan_diffs sd JOIN pipeline_runs pr ON pr.id = sd.pipeline_id
        ORDER BY pr.started_at DESC LIMIT 100
    """, "table", 15, 12, 12, 7),
]

TREND_CARDS = [
    ("AppSec Trends - Severity By Scan Day", """
        SELECT date_trunc('day', started_at) AS day, phase,
               sum(critical_count) AS critical, sum(high_count) AS high,
               sum(medium_count) AS medium, sum(low_count) AS low
        FROM scan_runs WHERE status = 'success'
        GROUP BY 1,2 ORDER BY 1 DESC, 2 LIMIT 150
    """, "table", 0, 0, 24, 8),
    ("AppSec Trends - Top CVEs", """
        SELECT v.vulnerability_id, v.severity, count(*) AS occurrences,
               count(DISTINCT sr.image_ref) AS images,
               max(v.fixed_version) AS available_fixed_version
        FROM vulnerabilities v JOIN scan_runs sr ON sr.id = v.scan_id
        GROUP BY 1,2 ORDER BY occurrences DESC LIMIT 100
    """, "table", 8, 0, 24, 8),
    ("AppSec Trends - Failed Policies", """
        SELECT pr.requested_image, pol.status, pol.created_at, pol.violations
        FROM policy_results pol JOIN pipeline_runs pr ON pr.id = pol.pipeline_id
        WHERE pol.status <> 'passed'
        ORDER BY pol.created_at DESC LIMIT 100
    """, "table", 16, 0, 24, 8),
]

def main() -> int:
    wait_for_metabase()
    session = setup_if_needed()
    database_id = ensure_database(session)
    dashboards = (
        ("AppSec Security Overview", CARDS),
        ("AppSec Manual Operations", MANUAL_CARDS),
        ("AppSec Vulnerability Trends", TREND_CARDS),
    )
    for title, cards in dashboards:
        dashboard_id = ensure_dashboard(session, title)
        for name, sql, display, row, col, size_x, size_y in cards:
            card_id = ensure_card(session, database_id, name, sql.strip(), display)
            add_card(session, dashboard_id, card_id, row, col, size_x, size_y)
    print(json.dumps({"metabase": BASE_URL, "dashboards": [item[0] for item in dashboards]}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
