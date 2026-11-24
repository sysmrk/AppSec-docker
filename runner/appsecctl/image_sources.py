"""Admin-ordered image pull sources. No implicit Docker Hub fallback when configured.

Registry hosts and optional repository prefixes are accepted. The input image's
repository path and tag/digest are preserved; Docker Hub official images use library/name.
Worker performs pulls, never the API, and never accepts arbitrary URLs.
"""
from __future__ import annotations

import os
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


def normalize_endpoint(value: str) -> str:
    raw = value.strip()
    if raw.lower().startswith("https://"):
        raw = raw[8:]
    host, sep, prefix = raw.partition("/")
    host = normalize_host(host)
    if sep and not re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*", prefix):
        raise ValueError("Enter a registry hostname and optional lowercase repository prefix")
    return host + ("/" + prefix if sep else "")


def configured_sources(conn: Any) -> list[dict[str, Any]] | None:
    rows = conn.execute(
        """SELECT name, host, priority FROM image_pull_sources
           WHERE enabled=true ORDER BY priority ASC, created_at ASC, name ASC"""
    ).fetchall()
    if rows:
        return [dict(row) for row in rows]
    configured = conn.execute(
        "SELECT EXISTS(SELECT 1 FROM image_pull_sources) AS configured"
    ).fetchone()
    if (configured and configured["configured"]) or os.getenv("APPSEC_REQUIRE_IMAGE_SOURCES", "false").lower() in ("1", "true", "yes"):
        return []
    return None


def canonical_ref(reference: str) -> str:
    host = image_registry(reference)
    path = image_path(reference)
    # The original explicit single-component path of non-Hub registries
    # must not be rewritten with Docker Hub's library namespace.
    if host and host not in ("docker.io", "index.docker.io", "registry-1.docker.io"):
        path = reference.split("/", 1)[1]
    else:
        host = "docker.io"
    if "@" not in path and ":" not in path.rsplit("/", 1)[-1]:
        path += ":latest"
    return host + "/" + path


def ordered_candidates(sources: list[dict[str, Any]] | None, references: list[str]) -> list[dict[str, Any]]:
    if sources is None:
        return [{"name": "direct (no source policy)", "ref": ref, "priority": 0} for ref in references]
    result = []
    seen = set()
    # Source priority is outermost, including alternative helper paths.
    for source in sources:
        endpoint = normalize_endpoint(source["host"])
        for requested in references:
            canonical = canonical_ref(requested)
            path = canonical.split("/", 1)[1]
            ref = endpoint + "/" + path
            # A direct upstream such as ghcr.io is not a Docker Hub proxy.
            if endpoint in ("ghcr.io", "docker.io", "mcr.microsoft.com", "quay.io") and canonical.split("/", 1)[0] != endpoint:
                continue
            if ref not in seen:
                seen.add(ref)
                result.append({"name": source["name"], "ref": ref, "priority": source["priority"]})
    return result


def candidates(conn: Any, requested: str) -> list[dict[str, Any]]:
    return ordered_candidates(configured_sources(conn), [requested])


def add(conn: Any, name: str, host: str, priority: int, enabled: bool = True) -> dict[str, Any]:
    if not _NAME.fullmatch(name):
        raise ValueError("Source alias must be 2-50 lowercase letters, digits, - or _")
    hostname = normalize_endpoint(host)
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
    return pull_ordered(candidates(conn, requested))


def pull_ordered(ordered: list[dict[str, Any]]) -> str:
    from .errors import safe_detail
    attempts = []
    if not ordered:
        raise RuntimeError("SOURCE_PULL_FAILED: All trusted image sources are disabled or none match; enable a compatible source in Registries.")
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
            print("IMAGE_SOURCE_FAILED priority=%s source=%s reason=%s" %
                  (item["priority"], item["name"], reason), flush=True)
        except subprocess.TimeoutExpired:
            attempts.append("%s (%s): pull timeout after 180 seconds" %
                            (item["name"], item["priority"]))
        except OSError as exc:
            attempts.append("%s (%s): docker unavailable (%s)" %
                            (item["name"], item["priority"], type(exc).__name__))
    raise RuntimeError("SOURCE_PULL_FAILED: " + "; ".join(attempts)[:1600])


def runtime_image(reference: str) -> str:
    """Resolve tool images through the same policy; retain legacy local use without policy."""
    from . import db
    with db.connect() as conn:
        sources = configured_sources(conn)
    if sources is None:
        return reference
    return pull_ordered(ordered_candidates(sources, [reference]))


def artifact_repositories(sources: list[dict[str, Any]] | None, configured: str) -> str:
    """OCI artifacts (Trivy databases) are not Docker runnable images."""
    if sources is None:
        return configured
    references = [x.strip() for x in configured.split(",") if x.strip()]
    ordered = ordered_candidates(sources, references)
    if not ordered:
        raise RuntimeError("SOURCE_PULL_FAILED: No approved repository for scanner database")
    return ",".join(x["ref"] for x in ordered)
