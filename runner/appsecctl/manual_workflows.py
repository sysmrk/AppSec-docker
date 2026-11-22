"""Persistent human-guided image workflows.

Every write is performed in a transaction. Users can scan without CI/CD,
inspect real findings, then explicitly approve registry changes.
"""
from __future__ import annotations

from uuid import UUID, uuid4
from typing import Any

from . import db


def _uuid(value: str) -> UUID:
    try:
        return UUID(str(value))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid workflow UUID") from exc


def _state(item: dict[str, Any]) -> str:
    decision = item.get("decision")
    if decision == "finish":
        return "completed"
    if decision == "approve_patch":
        patch_status = item.get("patch_job_status")
        if patch_status in ("failed", "canceled"):
            return "patch_failed"
        if patch_status != "success":
            return "patch_running" if patch_status == "running" else "patch_queued"
        if item.get("publish_decision") == "skip_publish":
            return "completed_without_publish"
        if item.get("publish_decision") == "approve_publish":
            pub_status = item.get("publish_job_status")
            if pub_status == "success":
                return "published"
            if pub_status in ("failed", "canceled"):
                return "publish_failed"
            return "publishing" if pub_status == "running" else "publish_queued"
        return "awaiting_publication" if item.get("pipeline_status") == "success" else "publication_blocked"
    scan_status = item.get("scan_job_status")
    if scan_status in ("failed", "canceled"):
        return "failed" if scan_status == "failed" else "canceled"
    if scan_status == "success" and item.get("pipeline_status") in ("success", "policy_failed"):
        return "awaiting_approval"
    return "scanning" if scan_status == "running" else "queued"


def create(conn, image: str, project_id: str | None, user_id: str) -> dict[str, str]:
    name = image.strip()
    if not name or len(name) > 1024 or any(x.isspace() for x in name):
        raise ValueError("enter a valid nonempty container image reference without whitespace")
    workflow_id = str(uuid4())
    scan_job = db.enqueue_pipeline(conn, name, project_id=project_id, mode="scan")
    conn.execute(
        """INSERT INTO manual_workflows (id, requested_image, project_id, created_by, scan_job_id)
           VALUES (%s, %s, %s, %s, %s)""",
        (workflow_id, name, project_id, user_id, scan_job),
    )
    return {"id": workflow_id, "image": name, "scan_job_id": scan_job, "state": "queued"}


# Do not accidentally expose global/unassigned runs across users. Unlike the
# legacy shared job model, these workflows are private to the creator/admin.
_WORKFLOW_QUERY = """
    SELECT w.id, w.requested_image, w.project_id, w.created_by,
           w.scan_job_id, w.patch_job_id, w.publish_job_id,
           w.decision, w.approved_by, w.approved_at,
           w.publish_decision, w.published_by, w.publish_approved_at,
           w.created_at, w.updated_at,
           s.status AS scan_job_status, s.last_error AS scan_error,
           p.status AS patch_job_status, p.last_error AS patch_error,
           pub.status AS publish_job_status, pub.last_error AS publish_error,
           COALESCE(p.pipeline_id, s.pipeline_id) AS pipeline_id,
           pr.status AS pipeline_status
    FROM manual_workflows w
    JOIN pipeline_jobs s ON s.id = w.scan_job_id
    LEFT JOIN pipeline_jobs p ON p.id = w.patch_job_id
    LEFT JOIN pipeline_jobs pub ON pub.id = w.publish_job_id
    LEFT JOIN pipeline_runs pr ON pr.id = COALESCE(p.pipeline_id, s.pipeline_id)
"""


def _permission_clause() -> str:
    return """(
        %s OR (w.project_id IS NULL AND w.created_by = %s) OR (
            w.project_id IS NOT NULL AND EXISTS (
                SELECT 1 FROM projects pr
                JOIN team_members tm ON tm.team_id = pr.team_id
                WHERE pr.id = w.project_id AND tm.user_id = %s
            )
        )
    )"""


def list_workflows(conn, user: dict[str, Any], limit: int = 40) -> list[dict[str, Any]]:
    uid = str(user["id"])
    rows = conn.execute(
        _WORKFLOW_QUERY + " WHERE " + _permission_clause() +
        " ORDER BY w.created_at DESC LIMIT %s",
        (user.get("role") == "admin", uid, uid, max(1, min(limit, 100))),
    ).fetchall()
    return [{**dict(row), "state": _state(dict(row))} for row in rows]


def get_workflow(conn, workflow_id: str, user: dict[str, Any]) -> dict[str, Any] | None:
    uid = str(user["id"])
    row = conn.execute(
        _WORKFLOW_QUERY + " WHERE w.id = %s AND " + _permission_clause(),
        (_uuid(workflow_id), user.get("role") == "admin", uid, uid),
    ).fetchone()
    return {**dict(row), "state": _state(dict(row))} if row else None


def decide(
    conn, workflow_id: str, user: dict[str, Any], action: str,
    confirm_push: bool = False,
) -> dict[str, Any]:
    if action not in ("finish", "approve_patch", "cancel", "approve_publish", "skip_publish"):
        raise ValueError("invalid decision")
    workflow = get_workflow(conn, workflow_id, user)
    if not workflow:
        raise PermissionError("workflow not found or access denied")
    if user["role"] not in ("admin", "operator"):
        raise PermissionError("operator permission required")
    if workflow["project_id"] and not db.user_can_access_project(
        conn, user, str(workflow["project_id"]), write=True
    ):
        raise PermissionError("project write access denied")
    if not workflow["project_id"] and user["role"] != "admin" and str(workflow["created_by"]) != str(user["id"]):
        raise PermissionError("shared workflow can only be changed by its creator")

    # Serialized decision across concurrent tabs and API requests.
    locked = conn.execute(
        """SELECT w.*, j.status AS scan_job_status, j.pipeline_id,
                  pr.status AS pipeline_status,
                  pj.status AS patch_job_status,
                  EXISTS (
                    SELECT 1 FROM scan_runs sr WHERE sr.pipeline_id = j.pipeline_id
                    AND sr.phase = 'original' AND sr.status = 'success'
                  ) AS original_scan_ok
           FROM manual_workflows w
           JOIN pipeline_jobs j ON j.id = w.scan_job_id
           LEFT JOIN pipeline_jobs pj ON pj.id=w.patch_job_id
           LEFT JOIN pipeline_runs pr ON pr.id = j.pipeline_id
           WHERE w.id = %s FOR UPDATE OF w""",
        (_uuid(workflow_id),),
    ).fetchone()
    if not locked:
        raise RuntimeError("workflow not found")

    if action in ("approve_publish", "skip_publish"):
        if locked["decision"] != "approve_patch" or locked["publish_decision"] is not None:
            raise RuntimeError("publication decision was already made or patch not approved")
        if locked["patch_job_status"] != "success":
            raise RuntimeError("the patched image must finish scanning before publication")
        prepared = conn.execute("""
            SELECT p.id, p.patched_image_ref, p.publication_status,
                   EXISTS(
                       SELECT 1 FROM scan_runs sr WHERE sr.pipeline_id=p.pipeline_id
                           AND sr.phase='patched' AND sr.status='success'
                   ) AS patched_scan_ok,
                   (SELECT status FROM policy_results pol WHERE pol.pipeline_id=p.pipeline_id
                    ORDER BY pol.created_at DESC LIMIT 1) AS final_policy
            FROM patch_runs p WHERE p.pipeline_id=%s AND p.status='success'
            ORDER BY p.started_at DESC LIMIT 1
        """, (locked["pipeline_id"],)).fetchone()
        if not prepared or not prepared["patched_scan_ok"]:
            raise RuntimeError("no successfully scanned patched image exists")
        if action == "skip_publish":
            conn.execute("""
                UPDATE manual_workflows
                SET publish_decision='skip_publish', published_by=%s,
                    publish_approved_at=now(), updated_at=now()
                WHERE id=%s
            """, (user["id"], _uuid(workflow_id)))
            return {"id": workflow_id, "state": "completed_without_publish"}
        if not confirm_push:
            raise ValueError("registry publication requires confirm_push=true")
        if prepared["final_policy"] != "passed" or locked["pipeline_status"] != "success":
            raise RuntimeError("cannot publish a patched image that failed the final policy")
        if prepared["publication_status"] != "prepared":
            raise RuntimeError("patched image is not in the approved prepared state")
        import os
        if os.environ.get("APPSEC_REQUIRE_SECOND_APPROVER", "false").lower() == "true":
            if str(locked["approved_by"]) == str(user["id"]):
                raise PermissionError("a different authorized operator must approve publishing")
        publish_job = str(uuid4())
        conn.execute("""
            INSERT INTO pipeline_jobs(id, requested_image, status, priority,
                                      project_id, mode, pipeline_id, max_attempts)
            VALUES (%s,%s,'queued',100,%s,'publish_patch',%s,1)
        """, (publish_job, locked["requested_image"], locked["project_id"], locked["pipeline_id"]))
        conn.execute("""
            UPDATE manual_workflows SET publish_decision='approve_publish',
                publish_job_id=%s, published_by=%s, publish_approved_at=now(),
                updated_at=now() WHERE id=%s
        """, (publish_job, user["id"], _uuid(workflow_id)))
        return {"id": workflow_id, "state": "publish_queued",
                "publish_job_id": publish_job, "destination": prepared["patched_image_ref"]}

    if locked["decision"] is not None:
        raise RuntimeError("workflow already decided")
    if action == "cancel":
        if locked["scan_job_status"] != "queued":
            raise RuntimeError("only a queued scan can be canceled")
        if not db.cancel_pipeline_job(conn, str(locked["scan_job_id"])):
            raise RuntimeError("job was already claimed")
        conn.execute("UPDATE manual_workflows SET updated_at = now() WHERE id = %s", (_uuid(workflow_id),))
        return {"id": workflow_id, "state": "canceled"}

    if (
        locked["scan_job_status"] != "success"
        or not locked["pipeline_id"]
        or locked["pipeline_status"] not in ("success", "policy_failed")
        or not locked["original_scan_ok"]
    ):
        raise RuntimeError("finish or patch requires a completed original scan and saved policy result")

    if action == "finish":
        conn.execute(
            """UPDATE manual_workflows SET decision = 'finish',
                      approved_by = %s, approved_at = now(), updated_at = now()
               WHERE id = %s""",
            (user["id"], _uuid(workflow_id)),
        )
        return {"id": workflow_id, "state": "completed"}

    # This approval authorizes local patch preparation and rescan only.
    # Publication always requires another explicit decision later.
    # Patching has one attempt; registry publication is a separate approval.
    patch_job = str(uuid4())
    conn.execute(
        """INSERT INTO pipeline_jobs (
             id, requested_image, status, priority, project_id, mode,
             pipeline_id, max_attempts
           ) VALUES (%s, %s, 'queued', 100, %s, 'continue_patch', %s, 1)""",
        (patch_job, locked["requested_image"], locked["project_id"], locked["pipeline_id"]),
    )
    conn.execute(
        """UPDATE manual_workflows SET decision = 'approve_patch',
                   patch_job_id = %s, approved_by = %s, approved_at = now(),
                   updated_at = now()
           WHERE id = %s""",
        (patch_job, user["id"], _uuid(workflow_id)),
    )
    return {"id": workflow_id, "state": "patch_queued", "patch_job_id": patch_job}
