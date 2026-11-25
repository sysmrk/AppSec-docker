"""Bounded, parameterized read models for the real AppSec Control Center.

Only database records from completed/running jobs are rendered. No fixtures,
mock data or fake counters are used in the UI.
"""
from __future__ import annotations

from typing import Any

from .errors import ui_error
from uuid import UUID


def _access(user: dict[str, Any]) -> tuple[bool, str]:
    return user.get("role") == "admin", str(user["id"])


def _rows(conn, query: str, params: tuple = ()) -> list[dict]:
    return [dict(row) for row in conn.execute(query, params).fetchall()]


def overview_data(conn, user: dict[str, Any]) -> dict[str, Any]:
    admin, uid = _access(user)
    pipeline_filter = """(%s OR p.project_id IS NULL OR EXISTS (
      SELECT 1 FROM projects pr JOIN team_members tm ON tm.team_id = pr.team_id
      WHERE pr.id = p.project_id AND tm.user_id = %s))"""
    security_filter = """(%s OR (sj.project_id IS NULL AND sj.requested_by = %s) OR EXISTS (
      SELECT 1 FROM projects pr JOIN team_members tm ON tm.team_id = pr.team_id
      WHERE pr.id = sj.project_id AND tm.user_id = %s))"""
    job_filter = """(%s OR j.project_id IS NULL OR EXISTS (
      SELECT 1 FROM projects pr JOIN team_members tm ON tm.team_id = pr.team_id
      WHERE pr.id = j.project_id AND tm.user_id = %s))"""

    stats = conn.execute(
        f"""SELECT count(*)::int AS total,
           count(*) FILTER (WHERE p.status = 'success')::int AS passed,
           count(*) FILTER (WHERE p.status = 'policy_failed')::int AS policy_failed,
           count(*) FILTER (WHERE p.status = 'failed')::int AS failed
           FROM pipeline_runs p WHERE {pipeline_filter}""",
        (admin, uid),
    ).fetchone()

    pipeline_rows = _rows(conn,
        f"""SELECT p.id, p.project_id, p.requested_image, p.status,
                  p.started_at, p.finished_at,
                  s.critical_count, s.high_count, s.medium_count, s.low_count
           FROM pipeline_runs p
           LEFT JOIN LATERAL (
             SELECT critical_count, high_count, medium_count, low_count
             FROM scan_runs WHERE pipeline_id = p.id
             ORDER BY started_at DESC LIMIT 1
           ) s ON true
           WHERE {pipeline_filter}
           ORDER BY p.started_at DESC LIMIT 30""",
        (admin, uid),
    )
    pending_rows = _rows(conn,
        f"""SELECT j.id, j.project_id, j.requested_image, j.mode, j.status,
                  j.pipeline_id, j.last_error, j.created_at
           FROM pipeline_jobs j
           WHERE {job_filter}
           ORDER BY j.created_at DESC LIMIT 30""",
        (admin, uid),
    )
    security_rows = _rows(conn,
        f"""SELECT sj.id, sj.project_id, sj.kind, sj.target, sj.status,
                  sj.finding_count, sj.high_count, sj.started_at, sj.finished_at
           FROM security_jobs sj
           WHERE {security_filter}
           ORDER BY sj.started_at DESC LIMIT 30""",
        (admin, uid, uid),
    )
    return {
        "summary": dict(stats),
        "pipelines": pipeline_rows,
        "pipeline_jobs": pending_rows,
        "security_jobs": security_rows,
    }


def image_workflow_history(conn, user: dict[str, Any], page: int = 1, limit: int = 20) -> dict[str, Any]:
    """One row per image workflow, including legacy/standalone image jobs."""
    from .manual_workflows import _WORKFLOW_QUERY, _permission_clause, _state

    admin, uid = _access(user)
    limit = max(1, min(int(limit), 20))
    page = max(1, int(page))
    # Manual workflows retain their stricter creator/team access rules. Exclude
    # their underlying jobs/pipelines from the legacy branches, even for users
    # who cannot see the corresponding manual workflow.
    cte = """
    WITH manual_rows AS (
    """ + _WORKFLOW_QUERY + " WHERE " + _permission_clause() + """
    ), history AS (
      SELECT 'manual'::text AS kind, m.id, m.requested_image, m.created_at,
             m.pipeline_id, m.pipeline_status, m.policy_status, m.decision,
             m.publish_decision, m.scan_job_status, m.patch_job_status, m.publish_job_status,
             NULL::text AS legacy_state
      FROM manual_rows m
      UNION ALL
      SELECT 'pipeline', p.id, p.requested_image, p.started_at,
             p.id, p.status, pol.status, NULL, NULL, NULL, NULL, NULL,
             COALESCE(j.status, p.status)::text
      FROM pipeline_runs p
      LEFT JOIN LATERAL (
        SELECT status FROM pipeline_jobs WHERE pipeline_id=p.id AND status IN ('queued','running')
        ORDER BY created_at DESC, id DESC LIMIT 1
      ) j ON true
      LEFT JOIN LATERAL (
        SELECT status FROM policy_results WHERE pipeline_id=p.id
        ORDER BY created_at DESC LIMIT 1
      ) pol ON true
      WHERE (%s OR p.project_id IS NULL OR EXISTS (
        SELECT 1 FROM projects pr JOIN team_members tm ON tm.team_id=pr.team_id
        WHERE pr.id=p.project_id AND tm.user_id=%s))
        AND NOT EXISTS (
          SELECT 1 FROM pipeline_jobs pj JOIN manual_workflows w
          ON pj.id IN (w.scan_job_id, w.patch_job_id, w.publish_job_id)
          WHERE pj.pipeline_id=p.id)
      UNION ALL
      SELECT 'job', j.id, j.requested_image, j.created_at,
             NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, j.status::text
      FROM pipeline_jobs j
      WHERE j.pipeline_id IS NULL
        AND (%s OR j.project_id IS NULL OR EXISTS (
          SELECT 1 FROM projects pr JOIN team_members tm ON tm.team_id=pr.team_id
          WHERE pr.id=j.project_id AND tm.user_id=%s))
        AND NOT EXISTS (
          SELECT 1 FROM manual_workflows w
          WHERE j.id IN (w.scan_job_id, w.patch_job_id, w.publish_job_id))
    )
    """
    params = (admin, uid, uid, admin, uid, admin, uid)
    total = int(conn.execute(cte + " SELECT count(*) AS total FROM history", params).fetchone()["total"])
    total_pages = max(1, (total + limit - 1) // limit)
    page = min(page, total_pages)
    rows = _rows(conn, cte + """
      SELECT h.*, s.critical_count, s.high_count,
             EXISTS (SELECT 1 FROM pipeline_jobs j WHERE j.pipeline_id=h.pipeline_id
                       AND j.status IN ('queued','running')) AS active
      FROM history h
      LEFT JOIN LATERAL (
        SELECT critical_count, high_count FROM scan_runs WHERE pipeline_id=h.pipeline_id
        ORDER BY started_at DESC, id DESC LIMIT 1
      ) s ON true
      ORDER BY h.created_at DESC, h.kind, h.id DESC LIMIT %s OFFSET %s
    """, params + (limit, (page - 1) * limit))
    items = []
    for row in rows:
        state = _state(row) if row["kind"] == "manual" else row["legacy_state"]
        if row["active"] or state in ("queued", "scanning", "patch_queued", "patch_running", "publish_queued", "publishing", "running"):
            reason = "Job is queued or running; wait until it finishes."
        elif not row["pipeline_id"]:
            reason = "No pipeline/report was created for this job."
        elif row["pipeline_status"] not in ("success", "failed", "policy_failed"):
            reason = "Pipeline has not finished executing."
        else:
            reason = None
        items.append({**row, "state": state, "bulk_eligible": reason is None,
                      "bulk_disabled_reason": reason})
    return {"items": items, "total": total, "page": page, "total_pages": total_pages, "limit": limit}


def pipeline_details(conn, pipeline_id: str) -> dict[str, Any]:
    pid = UUID(pipeline_id)
    pipelines = _rows(conn,
        """SELECT id, project_id, requested_image, status, started_at,
                  finished_at, error_message
           FROM pipeline_runs WHERE id = %s""", (pid,))
    if not pipelines:
        return {"error": "pipeline not found"}
    scans = _rows(conn,
        """SELECT id, phase, image_ref, status, critical_count, high_count,
                  medium_count, low_count, unknown_count, started_at, finished_at, error_message,
                  raw_report->'_appsec' AS evidence
           FROM scan_runs WHERE pipeline_id = %s ORDER BY started_at ASC""", (pid,))
    patches = _rows(conn,
        """SELECT id, local_image_ref, local_image_id, patched_image_ref, publication_status, published_at, published_digest, status, started_at, finished_at, error_message
           FROM patch_runs WHERE pipeline_id = %s ORDER BY started_at DESC LIMIT 10""", (pid,))
    diffs = _rows(conn,
        """SELECT original_scan_id, patched_scan_id, fixed_count, remaining_count, introduced_count, created_at,
                  (SELECT count(*) FROM jsonb_array_elements(COALESCE(fixed_vulnerabilities,'[]'::jsonb)) v WHERE COALESCE(v->>'severity','UNKNOWN') <> 'LOW')::int AS report_fixed_count,
                  (SELECT count(*) FROM jsonb_array_elements(COALESCE(remaining_vulnerabilities,'[]'::jsonb)) v WHERE COALESCE(v->>'severity','UNKNOWN') <> 'LOW')::int AS report_remaining_count,
                  (SELECT count(*) FROM jsonb_array_elements(COALESCE(introduced_vulnerabilities,'[]'::jsonb)) v WHERE COALESCE(v->>'severity','UNKNOWN') <> 'LOW')::int AS report_introduced_count
           FROM scan_diffs WHERE pipeline_id = %s ORDER BY created_at DESC LIMIT 1""", (pid,))
    policies = _rows(conn,
        """SELECT scan_id, status, violations, created_at FROM policy_results
           WHERE pipeline_id = %s ORDER BY created_at DESC LIMIT 3""", (pid,))
    reports = _rows(conn,
        """SELECT id, format, created_at FROM generated_reports
           WHERE resource_type = 'pipeline' AND resource_id = %s
           ORDER BY created_at DESC LIMIT 20""", (str(pid),))
    artifacts = _rows(conn,
        """SELECT id, scan_id, image_ref, kind, format, created_at FROM artifacts
           WHERE pipeline_id = %s ORDER BY created_at DESC""", (pid,))
    for item in pipelines + scans + patches:
        if item.get("error_message"):
            item["error"] = ui_error(item["error_message"], "scan")
            item["error_message"] = item["error"]["title"]
    return {
        "pipeline": pipelines[0], "scans": scans, "patches": patches,
        "diffs": diffs, "policies": policies, "reports": reports,
        "artifacts": artifacts,
    }


def scan_vulnerabilities(
    conn, scan_id: str, severity: str | None, limit: int = 100
) -> dict[str, Any]:
    sid = UUID(scan_id)
    max_rows = max(1, min(int(limit), 200))
    findings = _rows(conn,
        """SELECT vulnerability_id, target, pkg_name, installed_version,
                  fixed_version, severity, title, primary_url
           FROM vulnerabilities WHERE scan_id = %s
             AND ((%s IS NULL AND severity <> 'LOW') OR severity = %s)
           ORDER BY CASE severity WHEN 'CRITICAL' THEN 0
                 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
                 vulnerability_id LIMIT %s""",
        (sid, severity, severity, max_rows),
    )
    return {"scan_id": str(sid), "severity": severity, "limit": max_rows, "findings": findings}
