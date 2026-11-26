"""Pre-authorized local routes and cooperative workflow stop.

Registry publication is allowed only for a verified Copa patch, to the
explicit pre-start authorized destination, with a passing recommendation.
Local package removal requires explicit pre-start authorization and the
existing safety checks. Optimized candidates never publish automatically.
A stop request prevents subsequent stages/retries; an in-flight atomic tool
operation may finish before the worker acknowledges the stop.
"""
from __future__ import annotations

import os
from . import db, manual_workflows as mw, scan_evidence


class StopRequested(RuntimeError):
    pass


def requested(conn, kind, ident):
    if kind=="image":
        row=conn.execute("""SELECT 1 FROM manual_workflows WHERE stop_requested_at IS NOT NULL
             AND %s IN (scan_job_id,patch_job_id,publish_job_id)""",(ident,)).fetchone()
    elif kind=="optimization":
        row=conn.execute("""SELECT 1 FROM manual_workflows w JOIN optimization_runs o ON o.workflow_id=w.id
             WHERE o.id=%s AND w.stop_requested_at IS NOT NULL""",(ident,)).fetchone()
    else:
        return False
    return bool(row)


def stop(conn,wid,user):
    w=mw.get_workflow(conn,wid,user)
    if not w or user["role"] not in ("admin","operator"):
        raise PermissionError("Workflow write access required")
    if w["project_id"] and not db.user_can_access_project(conn,user,str(w["project_id"]),write=True):
        raise PermissionError("Project write access required")
    conn.execute("SELECT id FROM manual_workflows WHERE id=%s FOR UPDATE",(wid,))
    w=mw.get_workflow(conn,wid,user)
    if w.get("stop_requested_at"):
        return {"id":wid,"state":w["state"]}
    ids=[str(w[k]) for k in ("scan_job_id","patch_job_id","publish_job_id") if w.get(k)]
    jobs=conn.execute("SELECT id,status,mode FROM pipeline_jobs WHERE id=ANY(%s::uuid[]) FOR UPDATE",(ids,)).fetchall()
    if any(x["mode"]=="publish_patch" and x["status"]=="running" for x in jobs):
        raise ValueError("Registry push is already running; wait for publication reconciliation")
    active=conn.execute("SELECT id,state FROM optimization_runs WHERE workflow_id=%s AND state IN ('queued','planning','awaiting_approval','build_queued','building') FOR UPDATE",(wid,)).fetchall()
    if not active and not any(x["status"] in ("queued","running") for x in jobs) and w["state"] not in ("awaiting_approval","awaiting_publication","publication_blocked"):
        raise ValueError("Workflow has no remaining execution to stop")
    conn.execute("UPDATE manual_workflows SET stop_requested_at=now(),updated_at=now() WHERE id=%s",(wid,))
    conn.execute("UPDATE pipeline_jobs SET status='canceled',finished_at=now(),last_error='Stopped by user' WHERE id=ANY(%s::uuid[]) AND status='queued'",(ids,))
    conn.execute("UPDATE optimization_runs SET state='canceled',updated_at=now() WHERE workflow_id=%s AND state IN ('queued','awaiting_approval','build_queued')",(wid,))
    db.insert_audit(conn,str(user["id"]),"manual.stop","manual_workflow",wid,{})
    return {"id":wid,"state":"stopping" if any(x["status"]=="running" for x in jobs) or any(x["state"] in ("planning","building") for x in active) else "stopped"}


def advance(conn,job_id):
    """Only called after a successful completed image job. Idempotent under workflow lock."""
    row=conn.execute("""SELECT w.*, j.mode FROM manual_workflows w JOIN pipeline_jobs j
        ON j.id=%s AND j.id IN(w.scan_job_id,w.patch_job_id)
        WHERE w.execution_mode!='guided' AND w.stop_requested_at IS NULL AND j.status='success'
        FOR UPDATE OF w""",(job_id,)).fetchone()
    if not row:
        return
    wid=str(row["id"])
    actor=conn.execute("SELECT id,role,disabled FROM users WHERE id=%s",(row["created_by"],)).fetchone()
    if not actor or actor["disabled"] or actor["role"] not in ("admin","operator"):
        raise PermissionError("Workflow creator no longer authorized")
    if row["project_id"] and not db.user_can_access_project(conn,actor,str(row["project_id"]),write=True):
        raise PermissionError("Project write authorization revoked")
    workflow=mw.get_workflow(conn,wid,actor)
    if not workflow:
        raise PermissionError("Workflow access revoked")
    mode=row["execution_mode"]
    if mode=="auto_optimize":
        conn.execute("UPDATE manual_workflows SET auto_error=%s WHERE id=%s",
                     ("V4 preservation policy: package removal is disabled; start a new scan or patch workflow",wid))
        return
    unattended=row.get("unattended",False)
    if row["mode"]=="scan" and not row["decision"]:
        if mode=="scan_only":
            mw.decide(conn,wid,actor,"finish")
            return
        eligibility=scan_evidence.original_patch_eligibility(conn,workflow["pipeline_id"])
        if eligibility["code"]=="SCAN_EVIDENCE_INVALID":
            raise RuntimeError("Verified original scan unavailable; cannot determine Copa eligibility")
        from . import job_watch
        job_watch.emit("copa_eligible",eligibility["os_fixable"])
        if os.getenv("APPSEC_PATCH_ENABLED","false").lower() in ("1","true","yes") and (eligibility["eligible"] or unattended):
            mw.decide(conn,wid,actor,"approve_patch")
            db.insert_audit(conn,str(actor["id"]),"manual.auto_patch","manual_workflow",wid,{})
            return
        if eligibility["eligible"] or unattended:
            raise RuntimeError("Copa patching is disabled")
        job_watch.emit("copa_skipped")
        if mode=="auto_patch" and unattended:
            mw.decide(conn,wid,actor,"finish")
            db.insert_audit(conn,str(actor["id"]),"manual.auto_no_eligible_patch","manual_workflow",wid,{})
            if row.get("auto_destination"):
                conn.execute("UPDATE manual_workflows SET auto_error=%s WHERE id=%s",("No eligible patch; registry output not produced",wid))
            return
        if mode=="auto_patch":
            conn.execute("UPDATE manual_workflows SET auto_error='No eligible local Copa patch; review original findings' WHERE id=%s",(wid,))
            return
    if unattended and mode=="auto_patch" and row["mode"]=="continue_patch":
        destination=row.get("auto_destination")
        if destination:
            from .scan_evidence import publication_db_fresh
            if not publication_db_fresh(conn,workflow["pipeline_id"]):
                mw.decide(conn,wid,actor,"skip_publish")
                conn.execute("UPDATE manual_workflows SET auto_error=%s WHERE id=%s",
                             ("Automatic registry output blocked: fresh DB evidence required for both scans; local image retained",wid))
                return
            if workflow.get("policy_status") not in ("recommended","passed"):
                mw.decide(conn,wid,actor,"skip_publish")
                conn.execute("UPDATE manual_workflows SET auto_error=%s WHERE id=%s",
                             ("Registry output blocked by final recommendation; verified local patch retained",wid))
                return
            mw.decide(conn,wid,actor,"approve_publish",confirm_push=True,destination=destination)
            db.insert_audit(conn,str(actor["id"]),"manual.auto_publish","manual_workflow",wid,{"destination":destination})
        else:
            mw.decide(conn,wid,actor,"skip_publish")
            db.insert_audit(conn,str(actor["id"]),"manual.auto_keep_local","manual_workflow",wid,{})
        return
    if mode!="auto_optimize" or row["auto_step"]:
        return
    if row["mode"]=="scan" and row["decision"]:
        return
    from . import optimization
    stage="residual" if row["mode"]=="continue_patch" and workflow["state"]!="completed" else "original"
    result=optimization.create(conn,wid,actor,"debloat",stage,row["optimization_roots"],automatic=True)
    conn.execute("UPDATE manual_workflows SET auto_step=%s WHERE id=%s",(result["id"],wid))
