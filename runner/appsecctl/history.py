"""Admin-confirmed purge of one finished pipeline and its stored evidence.

Audit records are retained for accountability. Remote published images are
never deleted by a history action. Local patched image tags are queued for
worker-side removal, without granting Docker socket access to the API.
"""
from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import boto3
from botocore.client import Config
from .artifacts import secret_or_env


def remove_evidence(paths: set[str], pipeline_id: str) -> int:
    root = Path("/reports").resolve()
    local = set(root.glob("report-pipeline-" + pipeline_id + "*.html"))
    objects: dict[str, set[str]] = {}
    bucket = secret_or_env("S3_BUCKET", "appsec-artifacts")
    for item in paths:
        if item.startswith("s3://"):
            stored_bucket, slash, key = item[5:].partition("/")
            if not slash or stored_bucket != bucket or not key:
                raise ValueError("Evidence is outside the AppSec S3 bucket")
            objects.setdefault(stored_bucket, set()).add(key)
            # Uploads retain the original local copy.
            local.add(root / Path(key).name)
        else:
            path = Path(item).resolve()
            if not path.is_relative_to(root):
                raise ValueError("Evidence path is outside /reports; deletion refused")
            local.add(path)
    count = 0
    # If storage is enabled, check the pipeline prefix even when an older
    # report row was overwritten or a previous upload was not recorded.
    from .artifacts import s3_enabled
    if s3_enabled():
        objects.setdefault(bucket, set())
    if objects:
        client = boto3.client(
            "s3",
            endpoint_url=secret_or_env("S3_ENDPOINT_URL"),
            region_name=secret_or_env("S3_REGION", "us-east-1"),
            aws_access_key_id=secret_or_env("S3_ACCESS_KEY_ID"),
            aws_secret_access_key=secret_or_env("S3_SECRET_ACCESS_KEY"),
            config=Config(signature_version="s3v4"),
        )
        for name, keys in objects.items():
            # Include older versioned reports from previous AppSec revisions.
            pages = client.get_paginator("list_objects_v2").paginate(
                Bucket=name, Prefix="pipeline/" + pipeline_id + "/"
            )
            for page in pages:
                keys.update(v["Key"] for v in page.get("Contents", []))
            for key in keys:
                client.delete_object(Bucket=name, Key=key)
                count += 1
            # A versioned bucket needs separate lifecycle/retention handling.
            # Never claim physical erasure of object versions or backups.
    for path in local:
        if path.is_file():
            path.unlink()
            count += 1
    return count


def purge_pipeline(conn, pipeline_id: str) -> dict:
    pid = UUID(pipeline_id)
    # Same lock order as workflow decisions. No patch/publication approval can
    # enqueue a job after our active-job check while evidence is being removed.
    conn.execute("""
        SELECT w.id FROM manual_workflows w JOIN pipeline_jobs j ON j.id=w.scan_job_id
        WHERE j.pipeline_id=%s ORDER BY w.id FOR UPDATE OF w
    """, (pid,)).fetchall()
    pipeline = conn.execute("SELECT id, status FROM pipeline_runs WHERE id=%s FOR UPDATE", (pid,)).fetchone()
    if not pipeline:
        raise LookupError("Pipeline does not exist")
    if pipeline.get("status") in ("running", "queued"):
        raise RuntimeError("Pending or running jobs exist; finish or cancel them first")
    jobs = conn.execute(
        "SELECT status FROM pipeline_jobs WHERE pipeline_id=%s FOR UPDATE", (pid,)
    ).fetchall()
    if any(j["status"] in ("queued", "running") for j in jobs):
        raise RuntimeError("Pending or running jobs exist; finish or cancel them first")
    paths = set()
    for query, arg in [
        ("SELECT path FROM artifacts WHERE pipeline_id=%s", pid),
        ("SELECT report_path AS path FROM scan_runs WHERE pipeline_id=%s", pid),
        ("SELECT copa_report_path AS path FROM patch_runs WHERE pipeline_id=%s", pid),
    ]:
        paths.update(str(r["path"]) for r in conn.execute(query, (arg,)).fetchall() if r["path"])
    paths.update(str(r["path"]) for r in conn.execute(
        "SELECT path FROM generated_reports WHERE resource_type='pipeline' AND resource_id=%s",
        (pipeline_id,),
    ).fetchall() if r["path"])
    tags = {str(r["local_image_ref"]) for r in conn.execute(
        "SELECT local_image_ref FROM patch_runs WHERE pipeline_id=%s", (pid,)
    ).fetchall() if r["local_image_ref"]}
    # I/O first: if object storage cannot be reached, do not erase the DB view.
    removed = remove_evidence(paths, pipeline_id)
    candidate_images = [r["image_id"] for r in conn.execute(
        "SELECT image_id FROM scan_runs WHERE pipeline_id=%s", (pid,)
    ).fetchall()]
    source = conn.execute("SELECT source_image_id FROM pipeline_runs WHERE id=%s", (pid,)).fetchone()
    if source:
        candidate_images.append(source["source_image_id"])
    for tag in tags:
        conn.execute(
            """INSERT INTO pending_image_removals(id, image_ref)
               VALUES(%s,%s) ON CONFLICT(image_ref) DO UPDATE
               SET status='queued', last_error=NULL""",
            (str(uuid4()), tag),
        )
    conn.execute("""DELETE FROM manual_workflows
        WHERE scan_job_id IN (SELECT id FROM pipeline_jobs WHERE pipeline_id=%s)""", (pid,))
    conn.execute("DELETE FROM generated_reports WHERE resource_type='pipeline' AND resource_id=%s", (pipeline_id,))
    conn.execute("DELETE FROM artifacts WHERE pipeline_id=%s", (pid,))
    conn.execute("DELETE FROM scan_diffs WHERE pipeline_id=%s", (pid,))
    conn.execute("DELETE FROM policy_results WHERE pipeline_id=%s", (pid,))
    conn.execute("DELETE FROM patch_runs WHERE pipeline_id=%s", (pid,))
    conn.execute("DELETE FROM scan_runs WHERE pipeline_id=%s", (pid,))
    conn.execute("DELETE FROM pipeline_jobs WHERE pipeline_id=%s", (pid,))
    conn.execute("DELETE FROM pipeline_runs WHERE id=%s", (pid,))
    if candidate_images:
        conn.execute(
            """DELETE FROM images WHERE id = ANY(%s::uuid[])
               AND NOT EXISTS (SELECT 1 FROM scan_runs WHERE image_id=images.id)
               AND NOT EXISTS (SELECT 1 FROM pipeline_runs WHERE source_image_id=images.id)""",
            (list(set(candidate_images)),),
        )
    return {"status": "deleted", "evidence_removed": removed,
            "local_tags_queued_for_removal": len(tags),
            "published_registry_images_removed": False}


def claim_removal(conn):
    row = conn.execute("""
        WITH next AS (SELECT id FROM pending_image_removals
           WHERE status='queued' ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1)
        UPDATE pending_image_removals r SET status='running', attempts=attempts+1
        FROM next WHERE r.id=next.id RETURNING r.id, r.image_ref
    """).fetchone()
    return dict(row) if row else None


def finish_removal(conn, task, error: str | None):
    if error:
        conn.execute("UPDATE pending_image_removals SET status='failed',last_error=%s WHERE id=%s",
                     (error, task["id"]))
    else:
        conn.execute("DELETE FROM pending_image_removals WHERE id=%s", (task["id"],))
