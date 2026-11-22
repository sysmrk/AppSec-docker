from __future__ import annotations

import os
import time

from . import db
from .cli import run_pipeline
from .logging_utils import log_event
from .reports import notify, write_html_report, write_security_sarif
from .security import execute_security_job


def main() -> int:
    poll_seconds = int(os.environ.get("WORKER_POLL_SECONDS", "5"))
    queues = {item.strip() for item in os.environ.get("WORKER_QUEUES", "image,security").split(",") if item.strip()}
    log_event("worker.started", poll_seconds=poll_seconds, queues=sorted(queues))

    while True:
        job = None
        if "image" in queues:
            with db.connect() as conn:
                job = db.claim_next_job(conn)

        if job:
            job_id = str(job["id"])
            image_ref = str(job["requested_image"])
            project_id = str(job["project_id"]) if job.get("project_id") else None
            log_event("worker.image.claimed", job_id=job_id, image=image_ref)

            try:
                pipeline_id = run_pipeline(image_ref, project_id, mode=str(job.get("mode") or "scan"))
                with db.connect() as conn:
                    db.finish_job(conn, job_id, pipeline_id)
                    summary = db.pipeline_summary(conn, pipeline_id)
                notify("pipeline.success", summary)
                log_event("worker.image.finished", job_id=job_id, pipeline_id=pipeline_id)
            except BaseException as exc:
                with db.connect() as conn:
                    db.fail_job(conn, job_id, str(exc))
                log_event("worker.image.failed", level="error", job_id=job_id, error=str(exc))
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

        try:
            execute_security_job(security_job_id)
            with db.connect() as conn:
                detail = db.security_job_detail(conn, security_job_id)
            if detail:
                write_html_report("security_job", security_job_id, detail)
                write_security_sarif(security_job_id)
                notify("security.success", detail)
            log_event("worker.security.finished", job_id=security_job_id)
        except BaseException as exc:
            with db.connect() as conn:
                db.retry_or_fail_security_job(conn, security_job_id, str(exc))
            log_event("worker.security.failed", level="error", job_id=security_job_id, error=str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
