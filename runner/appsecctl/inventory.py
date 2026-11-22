"""Bounded, project-aware inventory of actual scanned container images."""
from __future__ import annotations

from uuid import UUID
from typing import Any


_ACCESS = """(
    %s OR (
      p.project_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM projects pr JOIN team_members tm ON tm.team_id=pr.team_id
        WHERE pr.id=p.project_id AND tm.user_id=%s
      )
    ) OR (
      p.project_id IS NULL AND EXISTS (
        SELECT 1 FROM manual_workflows w JOIN pipeline_jobs j ON j.id=w.scan_job_id
        WHERE j.pipeline_id=p.id AND w.created_by=%s
      )
    )
)"""


def list_images(conn, user: dict[str, Any], search: str = "", limit: int = 30, offset: int = 0) -> dict[str, Any]:
    safe_limit = max(1, min(limit, 100))
    safe_offset = max(0, min(offset, 10000))
    uid = str(user["id"])
    admin = user.get("role") == "admin"
    rows = conn.execute(f"""
        WITH visible AS (
            SELECT p.source_image_id AS image_id, p.id AS pipeline_id,
                   p.status, p.started_at, p.project_id
            FROM pipeline_runs p WHERE {_ACCESS}
        )
        SELECT i.id, i.name, count(v.pipeline_id)::int AS run_count,
               max(v.started_at) AS last_scanned_at,
               (array_agg(v.status ORDER BY v.started_at DESC))[1] AS last_status,
               s.id AS last_scan_id, s.critical_count, s.high_count,
               s.medium_count, s.low_count
        FROM images i
        JOIN visible v ON v.image_id=i.id
        LEFT JOIN LATERAL (
            SELECT sr.id, sr.critical_count, sr.high_count, sr.medium_count, sr.low_count
            FROM scan_runs sr JOIN visible vv ON vv.pipeline_id=sr.pipeline_id
            WHERE sr.image_id=i.id AND sr.status='success'
            ORDER BY sr.started_at DESC LIMIT 1
        ) s ON true
        WHERE i.name ILIKE %s
        GROUP BY i.id, i.name, s.id, s.critical_count, s.high_count,
                 s.medium_count, s.low_count
        ORDER BY last_scanned_at DESC, i.name
        LIMIT %s OFFSET %s
    """, (admin, uid, uid, "%" + search[:120] + "%", safe_limit, safe_offset)).fetchall()
    return {"items": [dict(row) for row in rows], "limit": safe_limit, "offset": safe_offset}


def image_history(conn, user: dict[str, Any], image_id: str, limit: int = 50) -> list[dict[str, Any]]:
    identifier = UUID(str(image_id))
    uid = str(user["id"])
    rows = conn.execute(f"""
        SELECT p.id, p.project_id, p.requested_image, p.status, p.started_at,
               p.finished_at, s.id AS scan_id, s.phase,
               s.critical_count, s.high_count, s.medium_count, s.low_count
        FROM pipeline_runs p
        LEFT JOIN LATERAL (
            SELECT sr.id, sr.phase, sr.critical_count, sr.high_count,
                   sr.medium_count, sr.low_count
            FROM scan_runs sr WHERE sr.pipeline_id=p.id AND sr.status='success'
            ORDER BY sr.started_at DESC LIMIT 1
        ) s ON true
        WHERE p.source_image_id=%s AND {_ACCESS}
        ORDER BY p.started_at DESC LIMIT %s
    """, (identifier, user.get("role") == "admin", uid, uid, max(1, min(limit, 100)))).fetchall()
    return [dict(row) for row in rows]


def compare(conn, left: str, right: str, limit: int = 100) -> dict[str, Any]:
    ids = [UUID(str(left)), UUID(str(right))]
    rows = conn.execute("""
        SELECT scan_id, vulnerability_id, severity, pkg_name, installed_version,
               fixed_version, target
        FROM vulnerabilities WHERE scan_id IN (%s,%s)
    """, tuple(ids)).fetchall()
    def key(row):
        return (str(row["vulnerability_id"] or ""), str(row["pkg_name"] or ""), str(row["target"] or ""))
    before = {key(r): dict(r) for r in rows if r["scan_id"] == ids[0]}
    after = {key(r): dict(r) for r in rows if r["scan_id"] == ids[1]}
    cap = max(1, min(limit, 200))
    return {
        "from_scan": str(ids[0]), "to_scan": str(ids[1]),
        "fixed_count": len(before.keys() - after.keys()),
        "remaining_count": len(before.keys() & after.keys()),
        "introduced_count": len(after.keys() - before.keys()),
        "fixed": [before[k] for k in sorted(before.keys() - after.keys())[:cap]],
        "introduced": [after[k] for k in sorted(after.keys() - before.keys())[:cap]],
    }
