"""Bounded, parameterized read models for the real AppSec Control Center.

Only database records from completed/running jobs are rendered. No fixtures,
mock data or fake counters are used in the UI.
"""
from __future__ import annotations

from typing import Any
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
    security_filter = """(%s OR sj.project_id IS NULL OR EXISTS (
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
        (admin, uid),
    )
    return {
        "summary": dict(stats),
        "pipelines": pipeline_rows,
        "pipeline_jobs": pending_rows,
        "security_jobs": security_rows,
    }


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
                  medium_count, low_count, unknown_count, started_at, finished_at, error_message
           FROM scan_runs WHERE pipeline_id = %s ORDER BY started_at ASC""", (pid,))
    patches = _rows(conn,
        """SELECT id, patched_image_ref, status, started_at, finished_at, error_message
           FROM patch_runs WHERE pipeline_id = %s ORDER BY started_at DESC LIMIT 10""", (pid,))
    diffs = _rows(conn,
        """SELECT fixed_count, remaining_count, introduced_count, created_at
           FROM scan_diffs WHERE pipeline_id = %s ORDER BY created_at DESC LIMIT 1""", (pid,))
    policies = _rows(conn,
        """SELECT status, violations, created_at FROM policy_results
           WHERE pipeline_id = %s ORDER BY created_at DESC LIMIT 3""", (pid,))
    reports = _rows(conn,
        """SELECT id, format, created_at FROM generated_reports
           WHERE resource_type = 'pipeline' AND resource_id = %s
           ORDER BY created_at DESC LIMIT 20""", (str(pid),))
    artifacts = _rows(conn,
        """SELECT id, kind, format, created_at FROM artifacts
           WHERE pipeline_id = %s ORDER BY created_at DESC LIMIT 20""", (pid,))
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
             AND (%s IS NULL OR severity = %s)
           ORDER BY CASE severity WHEN 'CRITICAL' THEN 0
                 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
                 vulnerability_id LIMIT %s""",
        (sid, severity, severity, max_rows),
    )
    return {"scan_id": str(sid), "severity": severity, "limit": max_rows, "findings": findings}
