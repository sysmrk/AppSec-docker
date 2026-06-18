from __future__ import annotations

import os
import time

from . import db


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
        count = enqueue_due()
        if count:
            print(f"enqueued {count} scheduled image(s)", flush=True)
        time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())
