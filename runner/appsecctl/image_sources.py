"""Admin-ordered image pull sources. No implicit Docker Hub fallback when configured.

Only registry hostnames are accepted. The input image's repository path and
tag/digest are preserved; an unqualified official image becomes library/name.
Worker performs pulls, never the API, and never accepts arbitrary URLs.
"""
from __future__ import annotations

import re
import subprocess
from typing import Any
from uuid import UUID, uuid4

from .registry import normalize_host, image_registry

_NAME = re.compile(r"^[a-z][a-z0-9_-]{1,49}$")
_SAFE_IMAGE = re.compile(r"^[a-zA-Z0-9_./:@-]{1,1024}$")


def image_path(reference: str) -> str:
    image = reference.strip()
    if not _SAFE_IMAGE.fullmatch(image) or ".." in image.split("/"):
        raise ValueError("Invalid image reference; enter repository:tag or a digest")
    host = image_registry(image)
    if host:
        image = image.split("/", 1)[1] if "/" in image else ""
    if not image:
        raise ValueError("Image repository path is required")
    if "/" not in image:
        image = "library/" + image
    return image


def candidates(conn: Any, requested: str) -> list[dict[str, Any]]:
    path = image_path(requested)
    rows = conn.execute(
        """SELECT name, host, priority FROM image_pull_sources
           WHERE enabled=true ORDER BY priority ASC, created_at ASC, name ASC"""
    ).fetchall()
    if not rows:
        configured = conn.execute(
            "SELECT EXISTS(SELECT 1 FROM image_pull_sources) AS configured"
        ).fetchone()
        if configured and configured["configured"]:
            # Fail closed: disabled sources NEVER authorize an unconfigured Docker Hub pull.
            return []
        # Backward-compatible direct pulls only on installations with no source policy.
        return [{"name": "direct (no source policy)", "ref": requested, "priority": 0}]
    return [{"name": row["name"], "ref": str(row["host"]).rstrip("/") + "/" + path,
             "priority": row["priority"]} for row in rows]


def add(conn: Any, name: str, host: str, priority: int, enabled: bool = True) -> dict[str, Any]:
    if not _NAME.fullmatch(name):
        raise ValueError("Source alias must be 2-50 lowercase letters, digits, - or _")
    hostname = normalize_host(host)
    if not isinstance(priority, int) or not 1 <= priority <= 10000:
        raise ValueError("Priority must be 1-10000 (lower is attempted first)")
    row = conn.execute(
        """INSERT INTO image_pull_sources (id, name, host, priority, enabled)
           VALUES (%s,%s,%s,%s,%s) RETURNING id, name, host, priority, enabled""",
        (str(uuid4()), name, hostname, priority, enabled),
    ).fetchone()
    return dict(row)


def list_sources(conn: Any) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute(
        "SELECT id, name, host, priority, enabled FROM image_pull_sources ORDER BY priority, created_at, name"
    ).fetchall()]


def remove(conn: Any, source_id: str) -> bool:
    return bool(conn.execute(
        "DELETE FROM image_pull_sources WHERE id=%s RETURNING id", (UUID(source_id),)
    ).fetchone())


def update(conn: Any, source_id: str, priority: int, enabled: bool) -> dict[str, Any] | None:
    if not 1 <= priority <= 10000:
        raise ValueError("Priority must be 1-10000")
    row = conn.execute(
        """UPDATE image_pull_sources SET priority=%s, enabled=%s
           WHERE id=%s RETURNING id, name, host, priority, enabled""",
        (priority, enabled, UUID(source_id)),
    ).fetchone()
    return dict(row) if row else None


def pull_image(conn: Any, requested: str) -> str:
    """Pull exclusively in configured priority order and keep the resolved ref for Copa.

    A successful pull is not proof the privileged BuildKit executor can reach the
    same registry. Copa MUST use the resolved mirror ref, not the original tag.
    """
    from .errors import safe_detail
    attempts = []
    ordered = candidates(conn, requested)
    if not ordered:
        raise RuntimeError("SOURCE_PULL_FAILED: All trusted image sources are disabled; enable a source in Registries.")
    for item in ordered:
        ref = item["ref"]
        try:
            result = subprocess.run(["docker", "pull", ref], capture_output=True,
                                    text=True, timeout=180, check=False)
            if result.returncode == 0:
                print("IMAGE_SOURCE_SELECTED priority=%s source=%s ref=%s" %
                      (item["priority"], item["name"], ref), flush=True)
                return ref
            reason = safe_detail(result.stderr or result.stdout or "")
            attempts.append("%s (%s): exit %s; %s" %
                            (item["name"], item["priority"], result.returncode, reason))
        except subprocess.TimeoutExpired:
            attempts.append("%s (%s): pull timeout after 180 seconds" %
                            (item["name"], item["priority"]))
        except OSError as exc:
            attempts.append("%s (%s): docker unavailable (%s)" %
                            (item["name"], item["priority"], type(exc).__name__))
    raise RuntimeError("SOURCE_PULL_FAILED: " + "; ".join(attempts)[:1600])
