from __future__ import annotations

import os
import time

from . import db, tool_updates


def enqueue_due() -> int:
    count = 0
    with db.connect() as conn:
        for item in db.due_scheduled_images(conn):
            db.enqueue_pipeline(conn, str(item["image_ref"]))
            db.mark_scheduled_enqueued(conn, str(item["id"]))
            count += 1
    return count


def main() -> int:
    interval = int(os.environ.get("SCHEDULER_POLL_SECONDS", "60"))
    print(f"scheduler started; polling every {interval}s", flush=True)

    while True:
        with db.connect() as conn:
            db.record_service_heartbeat(conn, "scheduler", os.environ.get("HOSTNAME", "scheduler"))
            conn.execute("DELETE FROM repository_job_credentials WHERE expires_at <= now() AND job_id IN (SELECT id FROM security_jobs WHERE status NOT IN ('queued','running'))")
        count = enqueue_due()
        if count:
            print(f"enqueued {count} scheduled image(s)", flush=True)
        try:
            tool_updates.apply_one()
            tool_updates.check_due()
        except Exception as exc:
            print("Tool update scheduler error: " + type(exc).__name__, flush=True)
        time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())
