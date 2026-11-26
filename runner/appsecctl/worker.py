from __future__ import annotations

import os
import time
import subprocess

from . import db
from .errors import safe_message, classify
from .cli import run_pipeline, continue_pipeline_patch, publish_prepared_patch
from .logging_utils import log_event
from . import job_watch
from .reports import notify, write_html_report, write_security_sarif
from .security import execute_security_job
from .history import claim_removal, finish_removal
from .errors import safe_detail


def main() -> int:
    os.environ["APPSEC_SUMMARY_COMPACT"] = "true"
    poll_seconds = int(os.environ.get("WORKER_POLL_SECONDS", "5"))
    queues = {item.strip() for item in os.environ.get("WORKER_QUEUES", "image,security").split(",") if item.strip()}
    log_event("worker.started", poll_seconds=poll_seconds, queues=sorted(queues))

    while True:
        with db.connect() as conn:
            db.record_service_heartbeat(
                conn, "worker:" + ",".join(sorted(queues)),
                os.environ.get("HOSTNAME", "worker"),
            )
        cleanup = None
        if "image" in queues:
            with db.connect() as conn:
                cleanup = claim_removal(conn)
        if cleanup:
            try:
                result = subprocess.run(["docker", "image", "rm", cleanup["image_ref"]],
                                        capture_output=True, text=True, timeout=90, check=False)
                diagnostic = result.stderr or result.stdout or ""
                error = None if result.returncode == 0 or "no such image" in diagnostic.lower() else (
                    "exit " + str(result.returncode) + ": " + safe_detail(diagnostic))
            except (OSError, subprocess.TimeoutExpired) as exc:
                error = type(exc).__name__
            with db.connect() as conn:
                finish_removal(conn, cleanup, error)
            log_event("worker.image.cleanup", image=cleanup["image_ref"],
                      result="success" if error is None else "failed")
            continue
        if "image" in queues:
            from . import optimization
            if optimization.enabled():
                with db.connect() as conn:
                    task=optimization.claim(conn)
                if task:
                    token=job_watch.CURRENT.set(("optimization",str(task["id"])))
                    job_watch.emit("optimization")
                    try:
                        status,plan,result=optimization.execute(task)
                        with db.connect() as conn:
                            optimization.finish(conn,task,status,plan,result)
                        job_watch.emit("failed" if status=="failed" else "success")
                    except Exception as exc:
                        with db.connect() as conn:
                            optimization.finish(conn,task,"failed",error=type(exc).__name__)
                        job_watch.emit("failed")
                    finally:
                        job_watch.CURRENT.reset(token)
                    continue
        job = None
        if "image" in queues:
            with db.connect() as conn:
                job = db.claim_next_job(conn)

        if job:
            job_id = str(job["id"])
            image_ref = str(job["requested_image"])
            project_id = str(job["project_id"]) if job.get("project_id") else None
            log_event("worker.image.claimed", job_id=job_id, image=image_ref)

            token = job_watch.CURRENT.set(("image",job_id))
            job_watch.emit("claimed")
            try:
                if str(job.get("mode")) in ("patch", "continue_patch", "publish_patch") and (
                    os.environ.get("APPSEC_PATCH_ENABLED", "false").lower() not in ("1", "true", "yes")
                ):
                    raise RuntimeError("patch and registry push disabled on this worker")
                if job.get("mode") in ("continue_patch", "publish_patch"):
                    if not job.get("pipeline_id"):
                        raise RuntimeError("approved continuation has no pipeline")
                    pipeline_id = (
                        continue_pipeline_patch(str(job["pipeline_id"]))
                        if job["mode"] == "continue_patch"
                        else publish_prepared_patch(str(job["pipeline_id"]), job_id)
                    )
                else:
                    pipeline_id = run_pipeline(image_ref, project_id, mode=str(job.get("mode") or "scan"), job_id=job_id)
                with db.connect() as conn:
                    db.finish_job(conn, job_id, pipeline_id)
                    summary = db.pipeline_summary(conn, pipeline_id)
                notify("pipeline.success", summary)
                log_event("worker.image.finished", job_id=job_id, pipeline_id=pipeline_id)
                job_watch.emit("success")
            except BaseException as exc:
                with db.connect() as conn:
                    db.fail_job(conn, job_id, safe_message(exc, 'image'))
                log_event("worker.image.failed", level="error", job_id=job_id, error_code=classify(exc, "image")["code"])
                job_watch.emit("failed")
            finally:
                job_watch.CURRENT.reset(token)
            continue

        security_job = None
        if "security" in queues:
            with db.connect() as conn:
                security_job = db.claim_next_security_job(conn)

        if not security_job:
            time.sleep(poll_seconds)
            continue

        security_job_id = str(security_job["id"])
        log_event("worker.security.claimed", job_id=security_job_id, target=security_job["target"])

        token = job_watch.CURRENT.set(("security",security_job_id))
        job_watch.emit("claimed")
        try:
            execute_security_job(security_job_id)
            with db.connect() as conn:
                detail = db.security_job_detail(conn, security_job_id)
            if detail:
                write_html_report("security_job", security_job_id, detail)
                write_security_sarif(security_job_id)
                notify("security.success", detail)
            log_event("worker.security.finished", job_id=security_job_id)
            job_watch.emit("success")
        except BaseException as exc:
            with db.connect() as conn:
                db.retry_or_fail_security_job(conn, security_job_id, safe_message(exc, 'repository'))
            log_event("worker.security.failed", level="error", job_id=security_job_id, error_code=classify(exc, "repository")["code"])
            job_watch.emit("failed")
        finally:
            job_watch.CURRENT.reset(token)


if __name__ == "__main__":
    raise SystemExit(main())
