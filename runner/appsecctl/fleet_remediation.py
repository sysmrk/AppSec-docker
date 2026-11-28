"""Opt-in local-only V4 UI pilot. No compiler, no package removal, no registry publication.

Vendor data is evidence, not authorization to install a newer distribution's
packages. Stable APT plans cover every installed package, not only reported fixes.
"""
from __future__ import annotations
import fcntl
import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from uuid import uuid4

from . import db, fix_discovery, native_apt, scan_evidence, apt_optimization as apt
from . import job_watch
from .errors import safe_message
from psycopg.types.json import Jsonb

URL="https://security-tracker.debian.org/tracker/data/json"
MAX_BYTES=128*1024*1024
TTL=6*3600

def enabled():
    return os.getenv("APPSEC_V4_FLEET_TEST","false").lower()=="true"

def supports(report):
    info=(report.get("Metadata") or {}).get("OS") or {}
    return info.get("Family")=="debian" and str(info.get("Name","")).split(".")[0] in ("12","13")

def _read_snapshot(path, *, fresh=False):
    with path.open("rb") as stream:
        modified=os.fstat(stream.fileno()).st_mtime
        if fresh and not 0<=time.time()-modified<TTL:
            raise ValueError("Vendor snapshot outside cache age limit")
        data=stream.read(MAX_BYTES+1)
    if not data or len(data)>MAX_BYTES:
        raise ValueError("Vendor snapshot size invalid")
    parsed=json.loads(data)
    if not isinstance(parsed,dict) or not parsed or not any(
            isinstance(v,dict) and any(isinstance(c,dict) and isinstance(c.get("releases"),dict)
            for c in v.values()) for v in parsed.values()):
        raise ValueError("Vendor snapshot invalid")
    return parsed,hashlib.sha256(data).hexdigest(),datetime.fromtimestamp(modified,timezone.utc).isoformat()

def cached_snapshot(path,origin):
    try:
        data,digest,modified=_read_snapshot(path,fresh=True)
        return data,digest,{"snapshot_origin":origin,"snapshot_file_mtime":modified,
                            "snapshot_age_limit_hours":TTL//3600}
    except (OSError,ValueError):
        return None

def vendor_error(exc):
    # Fixed safe diagnostics; do not expose proxy credentials or arbitrary stderr.
    if isinstance(exc,subprocess.CalledProcessError):
        reason={5:"proxy DNS failure",6:"DNS failure",7:"connection failed",
                18:"incomplete transfer",22:"HTTP error",28:"transfer timeout",
                35:"TLS handshake failed",60:"TLS certificate verification failed",
                63:"snapshot exceeds size limit"}.get(exc.returncode,"curl failed")
        return f"curl exit {exc.returncode}: {reason}"
    if isinstance(exc,(TimeoutError,subprocess.TimeoutExpired)):
        return "snapshot operation timed out"
    return type(exc).__name__

def snapshot():
    # Host file mtime is not an authenticated upstream publication timestamp.
    supplied=cached_snapshot(Path("/vendor-snapshots/debian-tracker.json"),"operator_host_snapshot")
    if supplied:
        return supplied
    # Existing persistent worker volume; single-host refresh lock.
    root=Path("/optimization/v4-vendor")
    root.mkdir(mode=0o700,exist_ok=True)
    dest=root/"debian-tracker.json"
    with (root/"refresh.lock").open("a") as lock:
        deadline=time.monotonic()+100
        while True:
            job_watch.checkpoint()
            try:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic()>=deadline:
                    raise TimeoutError("Vendor cache refresh busy")
                time.sleep(0.25)
        cached=cached_snapshot(dest,"worker_https_cache")
        if cached:
            return cached
        with tempfile.NamedTemporaryFile(dir=root,delete=False) as tmp:
            path=Path(tmp.name)
        try:
            subprocess.run(["curl","--disable","--fail","--silent","--show-error","--proto","=https",
                "--connect-timeout","15","--max-time","75","--max-filesize",str(MAX_BYTES),
                "--output",str(path),URL],check=True,timeout=80,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            job_watch.checkpoint()
            parsed,digest,modified=_read_snapshot(path,fresh=True)
            path.replace(dest)
            return parsed,digest,{"snapshot_origin":"worker_https_download",
                                  "snapshot_file_mtime":modified,"snapshot_age_limit_hours":TTL//3600}
        finally:
            path.unlink(missing_ok=True)

def discover(report):
    job_watch.emit("fix_discovery")
    if not supports(report):
        return {"status":"unsupported","message":"Independent vendor adapter currently supports Debian 12/13 only."}
    try:
        tracker,digest,provenance=snapshot()
        result=fix_discovery.audit(report,tracker)
        # Preserve each vendor finding in persisted metadata, not in the raw
        # scanner artifact; never fabricate or overwrite FixedVersion.
        return {"status":"completed","snapshot_sha256":digest,"snapshot_source":URL,**provenance,
                "summary":result["summary"],"findings":result["findings"],
                "message":"Vendor source evidence only; exact binary availability and compatibility require separate validation."}
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
        from .workflow_control import StopRequested
        if isinstance(exc,StopRequested):
            raise
        return {"status":"unavailable","message":"Vendor evidence unavailable: "+vendor_error(exc)+
                ". No conclusion about missing fixes; signed repository checks remain independent."}

def _record_plan(scan_id,plan):
    with db.connect() as conn:
        conn.execute("UPDATE scan_runs SET raw_report=jsonb_set(raw_report,'{_appsec,fleet_plan}',%s,true) WHERE id=%s",
                     (Jsonb(plan),scan_id))

def patch(scan_id):
    # The caller is the existing authorized patch job. No mid-run prompts.
    from . import optimization
    from .cli import patched_image_ref,source_repository
    with db.connect() as conn:
        scan=db.get_scan(conn,scan_id)
        eligibility=scan_evidence.patch_eligibility(scan)
        if eligibility["code"]=="SCAN_EVIDENCE_INVALID":
            raise RuntimeError("SCAN_EVIDENCE_INVALID: Verified original scan required")
        report=scan["raw_report"]
        image=report["_appsec"]["image_id"]
        source=scan["image_ref"]
        if scan_evidence.local_image_id(source)!=image:
            raise RuntimeError("SCAN_EVIDENCE_INVALID: Original image changed")
        mirrors=optimization.mirrors(conn)
        pipeline_id=scan["pipeline_id"]
        if pipeline_id is None:
            pipeline_id=db.create_pipeline(conn,str(scan["image_id"]),source)
            db.attach_scan_to_pipeline(conn,scan_id,pipeline_id)
        pipeline_id=str(pipeline_id)
    if not supports(report):
        _record_plan(scan_id,{"status":"unsupported","message":"V4 fleet pilot supports Debian 12/13 only; no legacy mutation fallback."})
        raise scan_evidence.NoFixableOS("V4 fleet pilot: unsupported distribution; no candidate")
    if not mirrors:
        _record_plan(scan_id,{"status":"blocked","message":"Configure approved package mirrors before starting the next workflow."})
        raise RuntimeError("V4 fleet pilot requires an approved package mirror")
    job_watch.emit("fleet_plan")
    try:
        plan=native_apt.plan(image,report,mirrors,generic=True)
    except Exception as exc:
        from .workflow_control import StopRequested
        if isinstance(exc,StopRequested):
            raise
        _record_plan(scan_id,{"status":"blocked","message":safe_message(exc,"patch_build")})
        raise
    summary={"status":"planned" if plan["updates"] else "no_updates","mirror":plan["mirror"],
             "updates":plan["updates"],"installed_package_count":len(plan["inventory"]),
             "plan_sha256":plan["plan_sha256"],"message":"All installed packages checked using stable, updates and security repositories. No backports or removals."}
    _record_plan(scan_id,summary)
    job_watch.emit("apt_upgrades",len(plan["updates"]))
    if not plan["updates"]:
        job_watch.emit("fleet_no_updates")
        raise scan_evidence.NoFixableOS("No eligible stable updates; original evidence retained")
    patch_id=str(uuid4())
    output=source_repository(source)+":patched-"+patch_id[:12]
    with db.connect() as conn:
        db.insert_patch_started(conn,patch_id,pipeline_id,scan_id,source,patched_image_ref(source,patch_id))
        conn.execute("UPDATE patch_runs SET execution_evidence=%s WHERE id=%s",
                     (Jsonb({"strategy":"fleet_native_apt","package_repository":{"mirror":plan["mirror"]},
                            "native_plan":summary,"publication_authorized":False}),patch_id))
    candidate=None
    tagged=False
    try:
        job_watch.emit("fleet_build")
        # Recheck the plan against the current authorized mirror set.
        with db.connect() as conn:
            authorized=optimization.mirrors(conn)
        candidate=native_apt.build(plan,report,plan["plan_sha256"],authorized,generic=True)
        job_watch.checkpoint()
        apt.run(["docker","tag",candidate["candidate_image_id"],output])
        tagged=True
        if scan_evidence.local_image_id(output)!=candidate["candidate_image_id"]:
            raise RuntimeError("SCAN_EVIDENCE_INVALID: Native candidate tag mismatch")
        with db.connect() as conn:
            db.update_patch_success(conn,patch_id,None)
            conn.execute("UPDATE patch_runs SET local_image_id=%s,local_image_ref=%s,publication_status='prepared',execution_evidence=execution_evidence || %s WHERE id=%s",
                         (candidate["candidate_image_id"],output,Jsonb({"native_candidate":candidate}),patch_id))
        return patch_id,output
    except BaseException as exc:
        with db.connect() as conn:
            db.update_patch_failed(conn,patch_id,safe_message(exc,"patch_build"))
        if tagged:
            subprocess.run(["docker","image","rm",output],check=False,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        raise
    finally:
        if candidate:
            subprocess.run(["docker","image","rm",candidate["candidate"]],check=False,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
