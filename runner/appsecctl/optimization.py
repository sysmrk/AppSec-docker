"""Explicit local-only optimization queue. API never holds a Docker socket.

Only admins may enqueue/approve in this initial opt-in worker deployment.
The separate optimization result never mutates patch_runs, policy_results,
or the publication-eligible scan. Local candidate verification is independent.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb
from . import apt_optimization as apt, apt_repository_review as repo_review
from . import db, job_watch, manual_workflows as mw, remediation_audit as audit
from . import candidate_review, scan_evidence, native_apt

ACTIVE=("queued","planning","awaiting_approval","build_queued","building")
OPERATIONS=("debloat","availability","inventory","upgrade")


def enabled():
    return os.getenv("APPSEC_ENABLE_OPTIMIZATION","false")=="true"


def mirrors(conn):
    row=conn.execute("SELECT mirrors FROM package_mirror_settings WHERE id=1").fetchone()
    return list(row["mirrors"]) if row else []


def set_mirrors(conn, user, selected):
    if not isinstance(selected,list) or len(selected)!=len(set(selected)) or not set(selected)<=set(apt.MIRRORS):
        raise ValueError("Choose an ordered list of supported mirror names")
    conn.execute("UPDATE package_mirror_settings SET mirrors=%s,updated_at=now() WHERE id=1",(Jsonb(selected),))
    db.insert_audit(conn,str(user["id"]),"optimization.mirrors.updated",metadata={"mirrors":selected})
    return selected


def lock_workflow(conn,wid,user):
    w=mw.get_workflow(conn,wid,user)
    if not w or user["role"]!="admin":
        raise PermissionError("Admin workflow access required")
    conn.execute("SELECT id FROM manual_workflows WHERE id=%s FOR UPDATE",(wid,)).fetchone()
    w=mw.get_workflow(conn,wid,user)
    if not w:
        raise PermissionError("Workflow unavailable")
    return w


def require_idle(w):
    if w.get("stop_requested_at"):
        raise ValueError("Workflow stopped")
    if w["state"] not in ("awaiting_approval","awaiting_publication","completed","completed_without_publish","published","publication_blocked","optimizing"):
        raise ValueError("Workflow must have completed scanning/patching")
    if not w.get("pipeline_id"):
        raise ValueError("No verified pipeline")


def create(conn,wid,user,operation,stage,roots):
    if not enabled():
        raise ValueError("Optimization worker disabled")
    if operation not in OPERATIONS or stage not in ("original","residual"):
        raise ValueError("Invalid optimization operation/stage")
    if operation=="debloat":
        if not roots or len(roots)!=len(set(roots)) or not set(roots)<=set(apt.OPTIONAL):
            raise ValueError("Select supported optional nginx modules")
    elif roots:
        raise ValueError("Removal roots only allowed for debloat")
    w=lock_workflow(conn,wid,user)
    require_idle(w)
    if w.get("unattended") and (w.get("auto_step") or w["execution_mode"]!="auto_optimize" or operation!="debloat" or sorted(roots)!=sorted(w["optimization_roots"])):
        raise ValueError("Unattended route is fixed at Start; create a new workflow")
    if conn.execute("SELECT 1 FROM optimization_runs WHERE workflow_id=%s AND state=ANY(%s)",(wid,list(ACTIVE))).fetchone():
        raise ValueError("An optimization task is already active")
    payload=db.pipeline_summary(conn,str(w["pipeline_id"]))
    phase="original" if stage=="original" else "patched"
    scan=next((s for s in reversed(payload.get("scans",[])) if s["phase"]==phase),None)
    if not audit.verified(scan) or (stage=="residual" and audit.analyze(payload)["comparison"]!="observed"):
        raise ValueError("Verified scan evidence unavailable")
    selected=mirrors(conn) if operation in ("availability","upgrade") else []
    if operation in ("availability","upgrade") and not selected:
        raise ValueError("Configure approved package mirrors first")
    ident=str(uuid4())
    conn.execute("""INSERT INTO optimization_runs(id,workflow_id,scan_id,created_by,stage,operation,roots,mirrors,state)
                 VALUES(%s,%s,%s,%s,%s,%s,%s,%s,'queued')""",
                 (ident,wid,str(scan["id"]),str(user["id"]),stage,operation,Jsonb(sorted(roots)),Jsonb(selected)))
    db.insert_audit(conn,str(user["id"]),"optimization.queued","manual_workflow",wid,{"task_id":ident,"operation":operation})
    return {"id":ident,"state":"queued"}


def decide(conn,wid,task_id,user,action,digest):
    if not enabled() and action!="cancel":
        raise ValueError("Optimization worker disabled")
    w=lock_workflow(conn,wid,user)
    row=conn.execute("SELECT * FROM optimization_runs WHERE id=%s AND workflow_id=%s FOR UPDATE",(task_id,wid)).fetchone()
    if not row:
        raise LookupError("Task not found")
    if action=="cancel":
        if row["state"] not in ("queued","awaiting_approval","build_queued"):
            raise ValueError("Only idle or queued tasks can be canceled")
        state="canceled"
    elif action=="approve":
        require_idle(w)
        if row["state"]!="awaiting_approval" or not row.get("plan") or digest!=row["plan"]["plan_sha256"]:
            raise ValueError("Plan missing, stale, or already decided")
        if os.getenv("APPSEC_REQUIRE_SECOND_APPROVER","false")=="true" and str(row["created_by"])==str(user["id"]):
            raise PermissionError("Different administrator must approve")
        state="build_queued"
    else:
        raise ValueError("Unknown decision")
    conn.execute("UPDATE optimization_runs SET state=%s,approved_by=%s,updated_at=now() WHERE id=%s",
                 (state,str(user["id"]) if action=="approve" else None,task_id))
    db.insert_audit(conn,str(user["id"]),"optimization."+action,"manual_workflow",wid,{"task_id":task_id,"plan_sha256":digest})
    return {"id":task_id,"state":state}


def list_runs(conn,wid,user):
    if not mw.get_workflow(conn,wid,user):
        raise LookupError("Workflow not found")
    rows=conn.execute("""SELECT id,stage,operation,state,roots,mirrors,plan,result,error_code,created_at,updated_at
                        FROM optimization_runs WHERE workflow_id=%s ORDER BY created_at DESC LIMIT 20""",(wid,)).fetchall()
    # Inventory in the plan is needed by the worker, not the browser.
    return [{**dict(row),"plan":{k:v for k,v in row["plan"].items() if k!="inventory"} if row["plan"] else None} for row in rows]


def claim(conn):
    row=conn.execute("""WITH next AS (
        SELECT id FROM optimization_runs WHERE state IN ('queued','build_queued')
        ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1
    ) UPDATE optimization_runs t SET state=CASE WHEN t.state='queued' THEN 'planning' ELSE 'building' END,
        updated_at=now() FROM next WHERE t.id=next.id RETURNING t.*""").fetchone()
    return dict(row) if row else None


def finish(conn,task,state,plan=None,result=None,error=None):
    # Lock workflow first, matching stop/decide lock order. Only the exact
    # automatically enqueued task is authorized by the immutable start choice.
    wid=str(task["workflow_id"])
    w=conn.execute("SELECT * FROM manual_workflows WHERE id=%s FOR UPDATE",(wid,)).fetchone()
    auto=bool(w and w.get("unattended") and w["execution_mode"]=="auto_optimize"
              and str(w.get("auto_step"))==str(task["id"]))
    if w and w.get("stop_requested_at"):
        state="canceled"
    actor=None
    if auto and state in ("awaiting_approval","completed"):
        actor=conn.execute("SELECT id,role,disabled FROM users WHERE id=%s",(w["created_by"],)).fetchone()
        if not actor or actor["disabled"] or actor["role"]!="admin":
            state,error="failed","Workflow creator authorization revoked"
        elif w["project_id"] and not db.user_can_access_project(conn,actor,str(w["project_id"]),write=True):
            state,error="failed","Project write authorization revoked"
    if auto and state=="awaiting_approval":
        if (os.getenv("APPSEC_REQUIRE_SECOND_APPROVER","false")=="true"
                or task["operation"]!="debloat" or not plan
                or sorted(plan.get("roots",[]))!=sorted(w["optimization_roots"])
                or plan.get("plan_sha256")!=apt.plan_digest(plan)):
            state,error="failed","Automatic removal authorization or plan validation failed"
    updated=conn.execute("""UPDATE optimization_runs SET state=%s,plan=COALESCE(%s,plan),result=COALESCE(%s,result),
                 error_code=%s,updated_at=now() WHERE id=%s AND state=%s RETURNING id""",
                 (state,Jsonb(plan) if plan is not None else None,Jsonb(result) if result is not None else None,
                  error,task["id"],task["state"])).fetchone()
    if not updated:
        return state
    if auto and state=="awaiting_approval":
        # Reuse the existing digest and role validation. Transactionally queue
        # the build: the intermediate approval state is never exposed.
        decide(conn,wid,str(task["id"]),actor,"approve",plan["plan_sha256"])
        db.insert_audit(conn,str(actor["id"]),"optimization.auto_approve","manual_workflow",wid,
                        {"task_id":str(task["id"]),"plan_sha256":plan["plan_sha256"],"roots":plan["roots"]})
        return "build_queued"
    if auto and state=="completed":
        mw.decide(conn,wid,actor,"skip_publish" if w["decision"]=="approve_patch" else "finish")
        db.insert_audit(conn,str(actor["id"]),"manual.auto_keep_local","manual_workflow",wid,{"task_id":str(task["id"])})
    elif auto and state in ("failed","canceled") and not w.get("stop_requested_at"):
        conn.execute("UPDATE manual_workflows SET auto_error=%s,updated_at=now() WHERE id=%s",
                     (error or "Automatic optimization did not complete",wid))
    return state


def manifest(folder):
    values={}
    for name in ("db","java-db"):
        path=folder/name
        if path.exists():
            if path.is_symlink() or not path.is_dir():
                raise ValueError("Invalid scanner DB directory")
            for entry in sorted(path.rglob("*")):
                if entry.is_symlink():
                    raise ValueError("Invalid scanner DB symlink")
                if entry.is_file():
                    with entry.open("rb") as stream:
                        values[str(entry.relative_to(folder))]=hashlib.file_digest(stream,"sha256").hexdigest()
    if not {"db/trivy.db","db/metadata.json"}<=values.keys():
        raise ValueError("Missing scanner DB snapshot")
    return values


def offline_compare(images, scanner_ref):
    """Scan base and candidate archives with one private frozen DB snapshot."""
    scanner=scan_evidence.local_image_id(scanner_ref)
    volume=os.getenv("APPSEC_OPTIMIZATION_VOLUME","appsec_optimization")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*",volume):
        raise ValueError("Invalid optimization volume")
    cache=os.getenv("TRIVY_CACHE_VOLUME","appsec_trivy_cache")
    if not cache or "," in cache or ":" in cache:
        raise ValueError("Invalid scanner cache mount")
    name="task-"+uuid4().hex
    root=Path("/optimization")/name
    root.mkdir(mode=0o700)
    try:
        # Trusted scanner image only; no Docker socket, no network. Source DB
        # cache is read-only. Check source bytes against copies before use.
        script='set -eu; d="/work/$1/frozen"; mkdir -p "$d"; for p in db java-db; do if [ -d "/source/$p" ]; then cp -a "/source/$p" "$d/"; diff -r "/source/$p" "$d/$p"; fi; done'
        apt.run(["docker","run","--rm","--pull=never","--network","none","--cap-drop","ALL",
                 "--security-opt","no-new-privileges:true","--user","0:0","-v",cache+":/source:ro",
                 "-v",volume+":/work","--entrypoint","/bin/sh",scanner,"-ec",script,"lab",name],300)
        frozen=root/"frozen"
        hashes=manifest(frozen)
        reports=[]
        for index,image in enumerate(images):
            job_watch.emit("rescan")
            tmp=root/("scan-"+str(index))
            tmp.mkdir()
            working=tmp/"cache"
            shutil.copytree(frozen,working)
            if manifest(working)!=hashes:
                raise ValueError("DB copy mismatch")
            archive=tmp/"image.tar"
            apt.run(["docker","image","save","--output",str(archive),image],600)
            rel="/work/"+name+"/scan-"+str(index)
            cmd=["docker","run","--rm","--pull=never","--network","none","--cap-drop","ALL",
                 "--security-opt","no-new-privileges:true","--user","0:0","-v",volume+":/work",
                 scanner,"image","--input",rel+"/image.tar","--cache-dir",rel+"/cache",
                 "--scanners","vuln","--pkg-types","os,library","--list-all-pkgs","--ignore-unfixed=false",
                 "--ignorefile","/dev/null","--skip-db-update","--skip-java-db-update","--offline-scan",
                 "--format","json","--output",rel+"/report.json"]
            # Same existing managed scanner timeout cleanup.
            from .cli import run_trivy_command
            run_trivy_command(cmd,"optimization-rescan",900)
            raw=json.loads((tmp/"report.json").read_text())
            scan_evidence.validate_report(raw,image)
            if manifest(working)!=hashes or manifest(frozen)!=hashes:
                raise ValueError("Scanner DB changed")
            raw["_appsec"]={"verified":True,"scope":audit.SCOPE,"image_id":image,"scanner_image":scanner}
            row={"id":str(index),"phase":"original" if index==0 else "patched","status":"success","raw_report":raw}
            if not audit.verified(row):
                raise ValueError("Verified scanner inventory unavailable")
            reports.append(row)
            archive.unlink()
            shutil.rmtree(tmp)
        return reports,hashes,scanner
    finally:
        shutil.rmtree(root,ignore_errors=True)


def execute(task):
    with db.connect() as conn:
        scan=db.get_scan(conn,str(task["scan_id"]))
        current=conn.execute("SELECT mirrors FROM package_mirror_settings WHERE id=1").fetchone()
        actor_id=task["approved_by"] if task["state"]=="building" else task["created_by"]
        actor=conn.execute("SELECT role,disabled FROM users WHERE id=%s",(actor_id,)).fetchone()
    if not actor or actor["role"]!="admin" or actor["disabled"]:
        raise PermissionError("Task actor authorization revoked")
    if not audit.verified(scan):
        raise ValueError("Scan no longer verified")
    raw=scan["raw_report"]
    image=raw["_appsec"]["image_id"]
    op=task["operation"]
    if task["state"]=="planning":
        if op=="availability":
            if not set(task["mirrors"])<=set(current["mirrors"]):
                raise ValueError("Mirror authorization revoked")
            result=repo_review.availability(image,task["mirrors"])
            return ("completed" if result["status"]=="repository_checked" else "failed"),None,result
        if op=="inventory":
            return "completed",None,repo_review.reconcile(image,raw)
        if op=="upgrade":
            if not set(task["mirrors"])<=set(current["mirrors"]):
                raise ValueError("Mirror authorization revoked")
            plan=native_apt.plan(image,raw,task["mirrors"])
            if not plan["updates"]:
                return "completed",plan,{"status":"no_available_upgrades","publication_authorized":False}
        else:
            plan=apt.plan_removal(image,task["roots"],raw)
        job_watch.emit("plan")
        return "awaiting_approval",plan,None
    if task["state"]!="building" or not task["approved_by"] or op not in ("debloat","upgrade"):
        raise ValueError("Invalid approved build task")
    # Check approver is still an enabled admin immediately before execution.
    with db.connect() as conn:
        approver=conn.execute("SELECT role,disabled FROM users WHERE id=%s",(task["approved_by"],)).fetchone()
    if not approver or approver["role"]!="admin" or approver["disabled"]:
        raise PermissionError("Approval revoked")
    if os.getenv("APPSEC_REQUIRE_SECOND_APPROVER","false")=="true" and str(task["created_by"])==str(task["approved_by"]):
        raise PermissionError("Different administrator must approve")
    apt.run(["docker","buildx","version"])
    job_watch.emit("build")
    candidate=(native_apt.build(task["plan"],raw,task["plan"]["plan_sha256"],current["mirrors"]) if op=="upgrade"
               else apt.build(task["plan"],raw,task["plan"]["plan_sha256"]))
    # Rescan the exact base and candidate, not an old report with a different DB.
    images=[image,candidate["candidate_image_id"]]
    if task["stage"]=="residual":
        with db.connect() as conn:
            original=conn.execute("SELECT * FROM scan_runs WHERE pipeline_id=%s AND phase='original' AND status='success' ORDER BY started_at DESC LIMIT 1",(scan["pipeline_id"],)).fetchone()
        if not audit.verified(original):
            raise ValueError("Verified original scan missing")
        original_id=original["raw_report"]["_appsec"]["image_id"]
        if original_id in images:
            raise ValueError("Unexpected duplicate candidate identity")
        images.insert(0,original_id)
    reports,hashes,scanner=offline_compare(images,raw["_appsec"]["scanner_image"])
    base={**reports[-2],"phase":"original"}
    comparison=audit.analyze({"scans":[base,reports[-1]]},benchmark=True)
    overall=audit.analyze({"scans":[reports[0],reports[-1]]},benchmark=True)
    if comparison["comparison"]!="benchmark_observed":
        raise ValueError("Candidate scan comparison unavailable")
    before,after=[candidate_review.counts(s["raw_report"]) for s in reports[-2:]]
    unknown=sum(c["coverage_unknown"] or 0 for c in comparison["cohorts"].values())
    result={**candidate,"rescan_required":False,"comparison":"frozen_db",
            "database_sha256":hashes,"scanner_image_id":scanner,
            "base_severity":before,"candidate_severity":after,"introduced":comparison["introduced"],
            "coverage_unknown":unknown,"base_findings":comparison["original_findings"],
            "candidate_findings":comparison["patched_findings"],
            "original_findings":overall["original_findings"],"overall_findings":overall["patched_findings"],
            "overall_introduced":overall["introduced"],
            "raw_report_sha256":[hashlib.sha256(audit.input_bytes(s["raw_report"])).hexdigest() for s in reports],
            "image_ids":images,
            "publication_authorized":False,"functional_test_passed":False,
            "security_review_required":True}
    blockers=[]
    if unknown or any(c["coverage_unknown"] for c in overall["cohorts"].values()): blockers.append("coverage_unknown")
    if result["introduced"] or result["overall_introduced"]: blockers.append("new_findings")
    if any(after[s]>before[s] for s in ("CRITICAL","HIGH","UNKNOWN")): blockers.append("severity_regression")
    if result["candidate_findings"]>=result["base_findings"]: blockers.append("no_net_reduction")
    result["comparison_blockers"]=blockers
    result["security_review_preferred"]=not blockers
    job_watch.emit("review")
    return "completed",None,result
