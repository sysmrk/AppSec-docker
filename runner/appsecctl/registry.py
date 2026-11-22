"""Registry metadata only. Never persist passwords or perform SSRF-prone API probes."""
from __future__ import annotations

import re
from urllib.parse import urlsplit
from uuid import uuid4
from typing import Any


_HOSTNAME = re.compile(r"^[A-Za-z0-9._:-]{1,255}$")
_ALIAS = re.compile(r"^[a-z][a-z0-9_-]{1,49}$")

def normalize_host(value: str) -> str:
    raw = value.strip()
    if raw.lower().startswith("https://"):
        raw = raw[8:]
    elif raw.lower().startswith("http://"):
        raise ValueError("Registry must use HTTPS")
    if not raw or any(x in raw for x in "/@?#\\ "):
        raise ValueError("Enter a hostname and optional port, without URL path or credentials")
    if not _HOSTNAME.fullmatch(raw):
        raise ValueError("Invalid registry hostname")
    parsed = urlsplit("https://" + raw)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid registry port") from exc
    if not parsed.hostname or (port is not None and not (1 <= port <= 65535)):
        raise ValueError("Invalid registry host or port")
    return raw.lower().rstrip(".")


def create(conn, name: str, host: str, project_id: str | None, allow_push: bool, actor_id: str) -> dict[str, Any]:
    if not _ALIAS.fullmatch(name):
        raise ValueError("Registry name must be lowercase letters, numbers, underscore or hyphen")
    hostname = normalize_host(host)
    identifier = str(uuid4())
    row = conn.execute("""
        INSERT INTO registry_connections(id, name, host, project_id, allow_push, created_by)
        VALUES (%s,%s,%s,%s,%s,%s)
        RETURNING id, name, host, project_id, allow_push, created_at
    """, (identifier, name, hostname, project_id, allow_push, actor_id)).fetchone()
    return dict(row)


def list_registries(conn, user: dict[str, Any]) -> list[dict[str, Any]]:
    uid = str(user["id"])
    admin = user.get("role") == "admin"
    rows = conn.execute("""
        SELECT r.id, r.name, r.host, r.project_id, r.allow_push, r.created_at
        FROM registry_connections r
        WHERE %s OR r.project_id IS NULL OR EXISTS (
            SELECT 1 FROM projects p
            JOIN team_members m ON m.team_id=p.team_id
            WHERE p.id=r.project_id AND m.user_id=%s
        )
        ORDER BY r.name
        LIMIT 100
    """, (admin, uid)).fetchall()
    return [dict(row) for row in rows]


def image_registry(image_ref: str) -> str | None:
    """Docker defaults unqualified refs to Docker Hub; explicit host is first segment."""
    first = image_ref.split("/", 1)[0]
    if "." in first or ":" in first or first == "localhost":
        return first.lower()
    return None


def preflight(conn, image: str, user: dict[str, Any]) -> dict[str, Any]:
    """Configuration-only readiness; does NOT claim that Docker can pull."""
    from . import db
    ref = image.strip()
    if not ref or len(ref) > 1024 or any(x.isspace() for x in ref):
        raise ValueError("Enter an image reference without spaces")
    configured = list_registries(conn, user)
    host = image_registry(ref)
    found = next((row for row in configured if row["host"] == host), None) if host else None
    workers = db.service_health_summary(conn)["heartbeats"]
    image_workers = [w for w in workers if w["service"].startswith("worker:") and "image" in w["service"]]
    recent = any(w["seconds_ago"] < 180 for w in image_workers)
    checks = [
        {"name": "Image reference", "status": "ok", "hint": "Reference format is accepted; image existence is not yet verified."},
        {"name": "Scanning worker", "status": "ok" if recent else "warning",
         "hint": "Recent worker heartbeat received." if recent else "No recent image Worker heartbeat. Ask an admin to run ./appsec doctor."},
        {"name": "Registry configuration", "status": "ok" if found else "warning",
         "hint": "Matched a registered HTTPS registry." if found else
                 ("Docker Hub default; credentials depend on Worker." if not host else
                  "Registry not registered; an admin can register it. Docker credentials must also exist on Worker.")},
        {"name": "Image pull", "status": "unverified",
         "hint": "The platform has not attempted to pull this image; a real scan confirms actual access."},
    ]
    return {"image": ref, "registry": found, "checks": checks, "ready_for_attempt": True}
