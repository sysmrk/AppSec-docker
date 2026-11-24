from __future__ import annotations

import json
import os
import base64
import hmac
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .sanitization import sanitize_security_detail


def database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    user = secret_or_env("POSTGRES_USER", "appsec")
    password = secret_or_env("POSTGRES_PASSWORD", "appsec-change-me")
    name = secret_or_env("POSTGRES_DB", "appsec")
    host = secret_or_env("POSTGRES_HOST", "postgres")
    port = secret_or_env("POSTGRES_PORT", "5432")
    return f"postgresql://{user}:{password}@{host}:{port}/{name}"


def connect() -> psycopg.Connection:
    return psycopg.connect(database_url(), row_factory=dict_row)


def init_schema(schema_path: str = "/db/schema.sql") -> None:
    sql = Path(schema_path).read_text(encoding="utf-8")
    with connect() as conn:
        conn.execute(sql)
        ensure_admin_user(conn)


def api_key_hash(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def password_hash(password: str) -> str:
    iterations = 240000
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, stored_hash: str | None) -> bool:
    if not stored_hash:
        return False
    try:
        algorithm, iterations, salt_b64, digest_b64 = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def ensure_admin_user(conn: psycopg.Connection) -> None:
    api_key = secret_or_env("APPSEC_ADMIN_API_KEY", "appsec-dev-key")
    password = secret_or_env("APPSEC_ADMIN_PASSWORD", "appsec-admin")
    row = conn.execute("SELECT id, password_hash FROM users WHERE username = 'admin'").fetchone()
    if row:
        if not row.get("password_hash") and password:
            conn.execute("UPDATE users SET password_hash = %s WHERE id = %s", (password_hash(password), row["id"]))
        return
    conn.execute(
        """
        INSERT INTO users (id, username, display_name, role, api_key_hash, password_hash)
        VALUES (%s, 'admin', 'AppSec Admin', 'admin', %s, %s)
        """,
        (str(uuid4()), api_key_hash(api_key), password_hash(password or "appsec-admin")),
    )


def secret_or_env(name: str, default: str | None = None) -> str | None:
    file_value = os.environ.get(f"{name}_FILE")
    if file_value:
        path = Path(file_value)
        if path.exists():
            return path.read_text(encoding="utf-8").strip()
    return os.environ.get(name, default)


def user_by_api_key(conn: psycopg.Connection, api_key: str) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT id, username, display_name, role, disabled, must_change_password, mfa_enabled, created_at, last_seen_at
        FROM users
        WHERE api_key_hash = %s AND disabled = false
        """,
        (api_key_hash(api_key),),
    ).fetchone()
    if not row:
        return None
    conn.execute("UPDATE users SET last_seen_at = now() WHERE id = %s", (row["id"],))
    return dict(row)


def authenticate_user(conn: psycopg.Connection, username: str, password: str) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT id, username, display_name, role, disabled, must_change_password,
               mfa_enabled, failed_login_count, locked_until, created_at, last_seen_at, password_hash
        FROM users
        WHERE username = %s AND disabled = false
        """,
        (username,),
    ).fetchone()
    if not row:
        return None
    locked_until = row.get("locked_until")
    if locked_until is not None and locked_until > datetime.now(timezone.utc):
        return None
    if not verify_password(password, row.get("password_hash")):
        conn.execute("""
            UPDATE users SET failed_login_count = failed_login_count + 1,
              locked_until = CASE WHEN failed_login_count + 1 >= 5
                THEN now() + interval '15 minutes' ELSE NULL END
            WHERE id = %s
        """, (row["id"],))
        return None
    if row.get("mfa_enabled"):
        # Do not reset brute-force lockout until the second factor succeeds.
        conn.execute("UPDATE users SET last_seen_at=now() WHERE id=%s", (row["id"],))
    else:
        conn.execute("""
            UPDATE users SET last_seen_at=now(), failed_login_count=0,
                locked_until=NULL WHERE id=%s
        """, (row["id"],))
    result = dict(row)
    result.pop("password_hash", None)
    result.pop("failed_login_count", None)
    result.pop("locked_until", None)
    return result


def create_session(conn: psycopg.Connection, user_id: str, hours: int = 12) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(36)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=hours)
    conn.execute(
        """
        INSERT INTO session_tokens (id, user_id, token_hash, expires_at)
        VALUES (%s, %s, %s, %s)
        """,
        (str(uuid4()), user_id, token_hash(token), expires_at),
    )
    return token, expires_at


def user_by_session(conn: psycopg.Connection, token: str) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT u.id, u.username, u.display_name, u.role, u.disabled, u.must_change_password, u.mfa_enabled, u.created_at, u.last_seen_at
        FROM session_tokens st
        JOIN users u ON u.id = st.user_id
        WHERE st.token_hash = %s
          AND st.revoked_at IS NULL
          AND st.expires_at > now()
          AND u.disabled = false
        """,
        (token_hash(token),),
    ).fetchone()
    if not row:
        return None
    conn.execute("UPDATE users SET last_seen_at = now() WHERE id = %s", (row["id"],))
    return dict(row)


def revoke_session(conn: psycopg.Connection, token: str) -> None:
    conn.execute(
        "UPDATE session_tokens SET revoked_at = now() WHERE token_hash = %s AND revoked_at IS NULL",
        (token_hash(token),),
    )


def list_teams(conn: psycopg.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT t.*, count(tm.user_id) AS member_count
        FROM teams t
        LEFT JOIN team_members tm ON tm.team_id = t.id
        GROUP BY t.id
        ORDER BY t.name
        """
    ).fetchall()
    return [dict(row) for row in rows]


def create_team(conn: psycopg.Connection, name: str, description: str | None = None) -> str:
    team_id = str(uuid4())
    conn.execute(
        "INSERT INTO teams (id, name, description) VALUES (%s, %s, %s)",
        (team_id, name, description),
    )
    return team_id


def add_team_member(conn: psycopg.Connection, team_id: str, user_id: str, role: str) -> None:
    conn.execute(
        """
        INSERT INTO team_members (team_id, user_id, role)
        VALUES (%s, %s, %s)
        ON CONFLICT (team_id, user_id) DO UPDATE SET role = EXCLUDED.role
        """,
        (team_id, user_id, role),
    )


def list_projects(conn: psycopg.Connection, user: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    if user and user.get("role") != "admin":
        rows = conn.execute(
            """
            SELECT p.*, t.name AS team_name
            FROM projects p
            LEFT JOIN teams t ON t.id = p.team_id
            JOIN team_members tm ON tm.team_id = p.team_id
            WHERE tm.user_id = %s
            ORDER BY p.name
            """,
            (user["id"],),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT p.*, t.name AS team_name
            FROM projects p
            LEFT JOIN teams t ON t.id = p.team_id
            ORDER BY p.name
            """
        ).fetchall()
    return [dict(row) for row in rows]


def create_project(
    conn: psycopg.Connection,
    name: str,
    slug: str,
    team_id: str | None = None,
    description: str | None = None,
    repo_url: str | None = None,
    registry_namespace: str | None = None,
) -> str:
    project_id = str(uuid4())
    conn.execute(
        """
        INSERT INTO projects (id, team_id, name, slug, description, repo_url, registry_namespace)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (project_id, team_id, name, slug, description, repo_url, registry_namespace),
    )
    return project_id


def user_can_access_project(conn: psycopg.Connection, user: dict[str, Any], project_id: str, write: bool = False) -> bool:
    if user.get("role") == "admin":
        return True
    row = conn.execute(
        """
        SELECT tm.role
        FROM projects p
        JOIN team_members tm ON tm.team_id = p.team_id
        WHERE p.id = %s AND tm.user_id = %s
        """,
        (project_id, user["id"]),
    ).fetchone()
    if not row:
        return False
    if not write:
        return True
    return row["role"] in ("owner", "maintainer")


def create_policy(
    conn: psycopg.Connection,
    name: str,
    rules: dict[str, Any],
    project_id: str | None = None,
    created_by: str | None = None,
) -> str:
    policy_id = str(uuid4())
    conn.execute(
        """
        INSERT INTO policies (id, project_id, name, rules, created_by)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (policy_id, project_id, name, Jsonb(rules), created_by),
    )
    return policy_id


def list_policies(conn: psycopg.Connection, project_id: str | None = None) -> list[dict[str, Any]]:
    if project_id:
        rows = conn.execute(
            """
            SELECT pol.*, p.name AS project_name
            FROM policies pol
            LEFT JOIN projects p ON p.id = pol.project_id
            WHERE pol.project_id = %s OR pol.project_id IS NULL
            ORDER BY pol.project_id NULLS FIRST, pol.created_at DESC
            """,
            (project_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT pol.*, p.name AS project_name
            FROM policies pol
            LEFT JOIN projects p ON p.id = pol.project_id
            ORDER BY pol.project_id NULLS FIRST, pol.created_at DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def active_policy_rules(conn: psycopg.Connection, project_id: str | None = None) -> dict[str, Any] | None:
    row = None
    if project_id:
        row = conn.execute(
            """
            SELECT rules
            FROM policies
            WHERE active = true AND project_id = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (project_id,),
        ).fetchone()
    if not row:
        row = conn.execute(
            """
            SELECT rules
            FROM policies
            WHERE active = true AND project_id IS NULL
            ORDER BY created_at DESC
            LIMIT 1
            """
        ).fetchone()
    return dict(row["rules"]) if row else None


def insert_audit(
    conn: psycopg.Connection,
    user_id: str | None,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> str:
    audit_id = str(uuid4())
    conn.execute(
        """
        INSERT INTO audit_logs (id, user_id, action, resource_type, resource_id, metadata)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (audit_id, user_id, action, resource_type, resource_id, Jsonb(metadata or {})),
    )
    return audit_id


def get_or_create_image(conn: psycopg.Connection, image_ref: str) -> str:
    normalized = image_ref.strip()
    row = conn.execute(
        "SELECT id FROM images WHERE normalized_name = %s",
        (normalized,),
    ).fetchone()
    if row:
        return str(row["id"])

    image_id = str(uuid4())
    conn.execute(
        """
        INSERT INTO images (id, name, normalized_name)
        VALUES (%s, %s, %s)
        """,
        (image_id, image_ref, normalized),
    )
    return image_id


def insert_scan_started(
    conn: psycopg.Connection,
    scan_id: str,
    pipeline_id: str | None,
    image_id: str,
    image_ref: str,
    phase: str,
) -> None:
    conn.execute(
        """
        INSERT INTO scan_runs (id, pipeline_id, image_id, image_ref, phase, status)
        VALUES (%s, %s, %s, %s, %s, 'running')
        """,
        (scan_id, pipeline_id, image_id, image_ref, phase),
    )


def update_scan_success(
    conn: psycopg.Connection,
    scan_id: str,
    report_path: str,
    report: dict[str, Any],
    counts: dict[str, int],
) -> None:
    conn.execute(
        """
        UPDATE scan_runs
        SET status = 'success',
            report_path = %s,
            raw_report = %s,
            critical_count = %s,
            high_count = %s,
            medium_count = %s,
            low_count = %s,
            unknown_count = %s,
            finished_at = now()
        WHERE id = %s
        """,
        (
            report_path,
            Jsonb(report),
            counts.get("CRITICAL", 0),
            counts.get("HIGH", 0),
            counts.get("MEDIUM", 0),
            counts.get("LOW", 0),
            counts.get("UNKNOWN", 0),
            scan_id,
        ),
    )


def update_scan_failed(conn: psycopg.Connection, scan_id: str, message: str) -> None:
    conn.execute(
        """
        UPDATE scan_runs
        SET status = 'failed', error_message = %s, finished_at = now()
        WHERE id = %s
        """,
        (message, scan_id),
    )


def insert_vulnerabilities(
    conn: psycopg.Connection,
    scan_id: str,
    vulnerabilities: list[dict[str, Any]],
) -> None:
    if not vulnerabilities:
        return

    rows = [
        (
            str(uuid4()),
            scan_id,
            item.get("target"),
            item.get("vulnerability_id"),
            item.get("pkg_name"),
            item.get("installed_version"),
            item.get("fixed_version"),
            item.get("severity"),
            item.get("title"),
            item.get("primary_url"),
        )
        for item in vulnerabilities
    ]
    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO vulnerabilities (
                id,
                scan_id,
                target,
                vulnerability_id,
                pkg_name,
                installed_version,
                fixed_version,
                severity,
                title,
                primary_url
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            rows,
        )


def create_pipeline(conn: psycopg.Connection, image_id: str, image_ref: str, project_id: str | None = None) -> str:
    pipeline_id = str(uuid4())
    conn.execute(
        """
        INSERT INTO pipeline_runs (id, source_image_id, requested_image, status, project_id)
        VALUES (%s, %s, %s, 'running', %s)
        """,
        (pipeline_id, image_id, image_ref, project_id),
    )
    return pipeline_id


def finish_pipeline(conn: psycopg.Connection, pipeline_id: str, status: str, error: str | None = None) -> None:
    conn.execute(
        """
        UPDATE pipeline_runs
        SET status = %s, error_message = %s, finished_at = now()
        WHERE id = %s
        """,
        (status, error, pipeline_id),
    )


def get_scan(conn: psycopg.Connection, scan_id: str) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT sr.*, pr.id AS pipeline_run_id
        FROM scan_runs sr
        LEFT JOIN pipeline_runs pr ON pr.id = sr.pipeline_id
        WHERE sr.id = %s
        """,
        (scan_id,),
    ).fetchone()
    if not row:
        raise RuntimeError(f"scan_id not found: {scan_id}")
    return dict(row)


def attach_scan_to_pipeline(conn: psycopg.Connection, scan_id: str, pipeline_id: str) -> None:
    conn.execute(
        "UPDATE scan_runs SET pipeline_id = %s WHERE id = %s",
        (pipeline_id, scan_id),
    )


def insert_patch_started(
    conn: psycopg.Connection,
    patch_id: str,
    pipeline_id: str,
    source_scan_id: str,
    source_image_ref: str,
    patched_image_ref: str,
) -> None:
    conn.execute(
        """
        INSERT INTO patch_runs (
            id,
            pipeline_id,
            source_scan_id,
            source_image_ref,
            patched_image_ref,
            status
        )
        VALUES (%s, %s, %s, %s, %s, 'running')
        """,
        (patch_id, pipeline_id, source_scan_id, source_image_ref, patched_image_ref),
    )


def update_patch_success(conn: psycopg.Connection, patch_id: str, report_path: str | None) -> None:
    conn.execute(
        """
        UPDATE patch_runs
        SET status = 'success', copa_report_path = %s, finished_at = now()
        WHERE id = %s
        """,
        (report_path, patch_id),
    )


def update_patch_failed(conn: psycopg.Connection, patch_id: str, message: str) -> None:
    conn.execute(
        """
        UPDATE patch_runs
        SET status = 'failed', error_message = %s, finished_at = now()
        WHERE id = %s
        """,
        (message, patch_id),
    )


def vulnerabilities_for_scan(conn: psycopg.Connection, scan_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT target, vulnerability_id, pkg_name, installed_version, fixed_version, severity, title, primary_url
        FROM vulnerabilities
        WHERE scan_id = %s
        ORDER BY severity, vulnerability_id, pkg_name, target
        """,
        (scan_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def insert_scan_diff(
    conn: psycopg.Connection,
    pipeline_id: str,
    original_scan_id: str,
    patched_scan_id: str,
    fixed: list[dict[str, Any]],
    remaining: list[dict[str, Any]],
    introduced: list[dict[str, Any]],
) -> str:
    diff_id = str(uuid4())
    conn.execute(
        """
        INSERT INTO scan_diffs (
            id,
            pipeline_id,
            original_scan_id,
            patched_scan_id,
            fixed_count,
            remaining_count,
            introduced_count,
            fixed_vulnerabilities,
            remaining_vulnerabilities,
            introduced_vulnerabilities
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            diff_id,
            pipeline_id,
            original_scan_id,
            patched_scan_id,
            len(fixed),
            len(remaining),
            len(introduced),
            Jsonb(fixed),
            Jsonb(remaining),
            Jsonb(introduced),
        ),
    )
    return diff_id


def insert_policy_result(
    conn: psycopg.Connection,
    pipeline_id: str,
    scan_id: str,
    status: str,
    rules: dict[str, Any],
    violations: list[dict[str, Any]],
) -> str:
    result_id = str(uuid4())
    conn.execute(
        """
        INSERT INTO policy_results (id, pipeline_id, scan_id, status, rules, violations)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (result_id, pipeline_id, scan_id, status, Jsonb(rules), Jsonb(violations)),
    )
    return result_id


def insert_artifact(
    conn: psycopg.Connection,
    pipeline_id: str | None,
    scan_id: str | None,
    image_ref: str,
    kind: str,
    format_name: str,
    path: str,
) -> str:
    artifact_id = str(uuid4())
    conn.execute(
        """
        INSERT INTO artifacts (id, pipeline_id, scan_id, image_ref, kind, format, path)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (artifact_id, pipeline_id, scan_id, image_ref, kind, format_name, path),
    )
    return artifact_id


def enqueue_pipeline(
    conn: psycopg.Connection, image_ref: str, priority: int = 100,
    project_id: str | None = None, mode: str = "scan",
) -> str:
    if mode not in ("scan", "patch"):
        raise ValueError("mode must be scan or patch")
    job_id = str(uuid4())
    conn.execute(
        """
        INSERT INTO pipeline_jobs (id, requested_image, status, priority, project_id, mode)
        VALUES (%s, %s, 'queued', %s, %s, %s)
        """,
        (job_id, image_ref, priority, project_id, mode),
    )
    return job_id


def claim_next_job(conn: psycopg.Connection) -> dict[str, Any] | None:
    row = conn.execute(
        """
        WITH next_job AS (
            SELECT id
            FROM pipeline_jobs
            WHERE status = 'queued'
              AND attempts < max_attempts
            ORDER BY priority ASC, created_at ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 1
        )
        UPDATE pipeline_jobs pj
        SET status = 'running',
            attempts = attempts + 1,
            started_at = now(),
            last_error = NULL
        FROM next_job
        WHERE pj.id = next_job.id
        RETURNING pj.*
        """
    ).fetchone()
    return dict(row) if row else None


def finish_job(conn: psycopg.Connection, job_id: str, pipeline_id: str) -> None:
    conn.execute(
        """
        UPDATE pipeline_jobs
        SET status = 'success', pipeline_id = %s, finished_at = now()
        WHERE id = %s
        """,
        (pipeline_id, job_id),
    )


def fail_job(conn: psycopg.Connection, job_id: str, message: str) -> None:
    conn.execute(
        """
        UPDATE pipeline_jobs
        SET status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'queued' END,
            last_error = %s,
            finished_at = CASE WHEN attempts >= max_attempts THEN now() ELSE NULL END
        WHERE id = %s
        """,
        (message, job_id),
    )


def list_jobs(conn: psycopg.Connection, limit: int = 20, user: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    is_admin = user is None or user.get("role") == "admin"
    user_id = str(user["id"]) if user else None
    rows = conn.execute(
        """
        SELECT j.id, j.requested_image, j.status, j.priority, j.attempts, j.max_attempts,
               j.pipeline_id, j.project_id, j.mode, j.last_error, j.created_at, j.started_at, j.finished_at
        FROM pipeline_jobs j
        WHERE %s OR j.project_id IS NULL OR EXISTS (
            SELECT 1 FROM projects p
            JOIN team_members tm ON tm.team_id = p.team_id
            WHERE p.id = j.project_id AND tm.user_id = %s
        )
        ORDER BY j.created_at DESC
        LIMIT %s
        """,
        (is_admin, user_id, max(1, min(limit, 100))),
    ).fetchall()
    return [dict(row) for row in rows]


def cancel_pipeline_job(conn: psycopg.Connection, job_id: str) -> bool:
    row = conn.execute(
        """
        UPDATE pipeline_jobs
        SET status = 'canceled', finished_at = now(), last_error = 'canceled by user'
        WHERE id = %s AND status = 'queued'
        RETURNING id
        """,
        (job_id,),
    ).fetchone()
    return bool(row)


def delete_queued_pipeline_job(conn: psycopg.Connection, job_id: str) -> bool:
    row = conn.execute(
        "DELETE FROM pipeline_jobs WHERE id = %s AND status = 'queued' RETURNING id",
        (job_id,),
    ).fetchone()
    return bool(row)


def search_history(conn: psycopg.Connection, query: str | None = None, limit: int = 50) -> dict[str, Any]:
    pattern = f"%{query or ''}%"
    pipelines = conn.execute(
        """
        SELECT id, requested_image, status, started_at, finished_at, error_message
        FROM pipeline_runs
        WHERE requested_image ILIKE %s OR id::text ILIKE %s OR status ILIKE %s
        ORDER BY started_at DESC
        LIMIT %s
        """,
        (pattern, pattern, pattern, limit),
    ).fetchall()
    security_jobs = conn.execute(
        """
        SELECT id, kind, target, status, finding_count, high_count, medium_count, low_count, info_count, started_at, finished_at, error_message
        FROM security_jobs
        WHERE target ILIKE %s OR id::text ILIKE %s OR kind ILIKE %s OR status ILIKE %s
        ORDER BY started_at DESC
        LIMIT %s
        """,
        (pattern, pattern, pattern, pattern, limit),
    ).fetchall()
    return {
        "pipelines": [dict(row) for row in pipelines],
        "security_jobs": [dict(row) for row in security_jobs],
    }


def dashboard_stats(conn: psycopg.Connection) -> dict[str, Any]:
    pipeline_counts = conn.execute(
        "SELECT status, count(*) AS count FROM pipeline_runs GROUP BY status"
    ).fetchall()
    security_counts = conn.execute(
        "SELECT kind, status, count(*) AS count FROM security_jobs GROUP BY kind, status"
    ).fetchall()
    recent_pipelines = conn.execute(
        """
        SELECT id, requested_image, status, started_at, finished_at
        FROM pipeline_runs
        ORDER BY started_at DESC
        LIMIT 8
        """
    ).fetchall()
    recent_security = conn.execute(
        """
        SELECT id, kind, target, status, finding_count, high_count, medium_count, low_count, info_count, started_at, finished_at
        FROM security_jobs
        ORDER BY started_at DESC
        LIMIT 8
        """
    ).fetchall()
    vuln_totals = conn.execute(
        """
        SELECT
            COALESCE(sum(critical_count), 0) AS critical,
            COALESCE(sum(high_count), 0) AS high,
            COALESCE(sum(medium_count), 0) AS medium,
            COALESCE(sum(low_count), 0) AS low
        FROM scan_runs
        WHERE status = 'success'
        """
    ).fetchone()
    security_severity_totals = conn.execute(
        """
        SELECT
            COALESCE(sum(high_count), 0) AS high,
            COALESCE(sum(medium_count), 0) AS medium,
            COALESCE(sum(low_count), 0) AS low,
            COALESCE(sum(info_count), 0) AS info
        FROM security_jobs
        WHERE status = 'success'
        """
    ).fetchone()
    fix_totals = conn.execute(
        """
        SELECT
            COALESCE(sum(fixed_count), 0) AS fixed,
            COALESCE(sum(remaining_count), 0) AS remaining,
            COALESCE(sum(introduced_count), 0) AS introduced
        FROM scan_diffs
        """
    ).fetchone()
    reports = conn.execute(
        """
        SELECT format, count(*) AS count
        FROM generated_reports
        GROUP BY format
        ORDER BY format
        """
    ).fetchall()
    return {
        "pipeline_counts": [dict(row) for row in pipeline_counts],
        "security_counts": [dict(row) for row in security_counts],
        "recent_pipelines": [dict(row) for row in recent_pipelines],
        "recent_security_jobs": [dict(row) for row in recent_security],
        "vulnerability_totals": dict(vuln_totals or {}),
        "security_severity_totals": dict(security_severity_totals or {}),
        "fix_totals": dict(fix_totals or {}),
        "report_counts": [dict(row) for row in reports],
    }


def get_pipeline(conn: psycopg.Connection, pipeline_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM pipeline_runs WHERE id = %s", (pipeline_id,)).fetchone()
    return dict(row) if row else None


def list_audit_logs(conn: psycopg.Connection, limit: int = 100) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT al.id, u.username, al.action, al.resource_type, al.resource_id, al.metadata, al.created_at
        FROM audit_logs al
        LEFT JOIN users u ON u.id = al.user_id
        ORDER BY al.created_at DESC
        LIMIT %s
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def list_users(conn: psycopg.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT id, username, display_name, role, disabled, must_change_password,
               failed_login_count, locked_until, password_changed_at, api_key_rotated_at,
               mfa_enabled, created_at, last_seen_at
        FROM users
        ORDER BY created_at
        """
    ).fetchall()
    return [dict(row) for row in rows]


def create_user(
    conn: psycopg.Connection,
    username: str,
    display_name: str,
    role: str,
    api_key: str,
    password: str | None = None,
) -> str:
    user_id = str(uuid4())
    conn.execute(
        """
        INSERT INTO users (id, username, display_name, role, api_key_hash, password_hash)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (user_id, username, display_name, role, api_key_hash(api_key), password_hash(password) if password else None),
    )
    return user_id


def insert_security_job_started(
    conn: psycopg.Connection,
    job_id: str,
    kind: str,
    target: str,
    requested_by: str | None = None,
    profile: str = "standard",
) -> None:
    conn.execute(
        """
        INSERT INTO security_jobs (id, kind, target, status, requested_by, profile)
        VALUES (%s, %s, %s, 'running', %s, %s)
        """,
        (job_id, kind, target, requested_by, profile),
    )


def enqueue_security_job(
    conn: psycopg.Connection,
    kind: str,
    target: str,
    requested_by: str | None = None,
    priority: int = 100,
    profile: str = "standard",
    project_id: str | None = None,
) -> str:
    job_id = str(uuid4())
    conn.execute(
        """
        INSERT INTO security_jobs (id, kind, target, status, requested_by, priority, profile, project_id)
        VALUES (%s, %s, %s, 'queued', %s, %s, %s, %s)
        """,
        (job_id, kind, target, requested_by, priority, profile, project_id),
    )
    return job_id


def claim_next_security_job(conn: psycopg.Connection) -> dict[str, Any] | None:
    row = conn.execute(
        """
        WITH next_job AS (
            SELECT id
            FROM security_jobs
            WHERE status = 'queued'
              AND attempts < max_attempts
            ORDER BY priority ASC, started_at ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 1
        )
        UPDATE security_jobs sj
        SET status = 'running',
            attempts = attempts + 1,
            last_error = NULL,
            started_at = now(),
            finished_at = NULL
        FROM next_job
        WHERE sj.id = next_job.id
        RETURNING sj.*
        """
    ).fetchone()
    return dict(row) if row else None


def update_security_job_success(
    conn: psycopg.Connection,
    job_id: str,
    report_path: str,
    raw_report: dict[str, Any],
    counts: dict[str, int],
) -> None:
    conn.execute(
        """
        UPDATE security_jobs
        SET status = 'success',
            report_path = %s,
            raw_report = %s,
            finding_count = %s,
            high_count = %s,
            medium_count = %s,
            low_count = %s,
            info_count = %s,
            finished_at = now()
        WHERE id = %s
        """,
        (
            report_path,
            Jsonb(raw_report),
            counts.get("total", 0),
            counts.get("high", 0),
            counts.get("medium", 0),
            counts.get("low", 0),
            counts.get("info", 0),
            job_id,
        ),
    )


def update_security_job_failed(conn: psycopg.Connection, job_id: str, message: str) -> None:
    conn.execute(
        """
        UPDATE security_jobs
        SET status = 'failed', error_message = %s, finished_at = now()
        WHERE id = %s
        """,
        (message, job_id),
    )


def retry_or_fail_security_job(conn: psycopg.Connection, job_id: str, message: str) -> None:
    conn.execute(
        """
        UPDATE security_jobs
        SET status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'queued' END,
            last_error = %s,
            error_message = CASE WHEN attempts >= max_attempts THEN %s ELSE error_message END,
            finished_at = CASE WHEN attempts >= max_attempts THEN now() ELSE NULL END
        WHERE id = %s
        """,
        (message, message, job_id),
    )


def insert_security_findings(
    conn: psycopg.Connection,
    job_id: str,
    findings: list[dict[str, Any]],
) -> None:
    if not findings:
        return
    rows = [
        (
            str(uuid4()),
            job_id,
            item.get("rule_id"),
            item.get("severity"),
            item.get("title"),
            item.get("description"),
            item.get("location"),
            item.get("evidence"),
            Jsonb(item.get("metadata") or {}),
        )
        for item in findings
    ]
    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO security_findings (
                id, job_id, rule_id, severity, title, description, location, evidence, metadata
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            rows,
        )


def list_security_jobs(conn: psycopg.Connection, limit: int = 50, user: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    is_admin = user is None or user.get("role") == "admin"
    user_id = str(user["id"]) if user else None
    rows = conn.execute(
        """
        SELECT sj.id, sj.kind, sj.target, sj.status, sj.finding_count, sj.high_count, sj.medium_count,
               sj.low_count, sj.info_count, sj.started_at, sj.finished_at, sj.error_message,
               sj.project_id, u.username AS requested_by
        FROM security_jobs sj
        LEFT JOIN users u ON u.id = sj.requested_by
        WHERE %s OR sj.project_id IS NULL OR EXISTS (
            SELECT 1 FROM projects p
            JOIN team_members tm ON tm.team_id = p.team_id
            WHERE p.id = sj.project_id AND tm.user_id = %s
        )
        ORDER BY sj.started_at DESC
        LIMIT %s
        """,
        (is_admin, user_id, max(1, min(limit, 100))),
    ).fetchall()
    return [dict(row) for row in rows]


def cancel_security_job(conn: psycopg.Connection, job_id: str) -> bool:
    row = conn.execute(
        """
        UPDATE security_jobs
        SET status = 'canceled',
            finished_at = now(),
            last_error = 'canceled by user',
            error_message = 'canceled by user'
        WHERE id = %s AND status = 'queued'
        RETURNING id
        """,
        (job_id,),
    ).fetchone()
    return bool(row)


def delete_queued_security_job(conn: psycopg.Connection, job_id: str) -> bool:
    row = conn.execute(
        "DELETE FROM security_jobs WHERE id = %s AND status = 'queued' RETURNING id",
        (job_id,),
    ).fetchone()
    return bool(row)


def security_job_detail(conn: psycopg.Connection, job_id: str) -> dict[str, Any] | None:
    job = conn.execute("SELECT * FROM security_jobs WHERE id = %s", (job_id,)).fetchone()
    if not job:
        return None
    findings = conn.execute(
        """
        SELECT sf.id, sf.rule_id, sf.severity, sf.title, sf.description, sf.location, sf.evidence,
               sf.metadata, sf.created_at,
               ar.id AS accepted_risk_id, ar.reason AS accepted_reason, ar.owner AS accepted_owner,
               ar.expires_at AS accepted_expires_at
        FROM security_findings sf
        LEFT JOIN accepted_risks ar ON ar.finding_id = sf.id
        WHERE sf.job_id = %s
        ORDER BY sf.created_at
        LIMIT 200
        """,
        (job_id,),
    ).fetchall()
    reports = list_generated_reports(conn, "security_job", job_id)
    return sanitize_security_detail({"job": dict(job), "findings": [dict(row) for row in findings], "reports": reports})


def accept_security_finding(
    conn: psycopg.Connection,
    finding_id: str,
    reason: str,
    owner: str,
    expires_at: str | None,
    accepted_by: str | None,
) -> str:
    risk_id = str(uuid4())
    conn.execute(
        """
        INSERT INTO accepted_risks (id, finding_id, reason, owner, expires_at, accepted_by)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (risk_id, finding_id, reason, owner, expires_at, accepted_by),
    )
    return risk_id


def insert_generated_report(
    conn: psycopg.Connection,
    resource_type: str,
    resource_id: str,
    format_name: str,
    path: str,
) -> str:
    report_id = str(uuid4())
    conn.execute(
        """
        INSERT INTO generated_reports (id, resource_type, resource_id, format, path)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (report_id, resource_type, resource_id, format_name, path),
    )
    return report_id


def list_generated_reports(conn: psycopg.Connection, resource_type: str, resource_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT id, resource_type, resource_id, format, path, created_at
        FROM generated_reports
        WHERE resource_type = %s AND resource_id = %s
        ORDER BY created_at DESC
        """,
        (resource_type, resource_id),
    ).fetchall()
    return [dict(row) for row in rows]


def latest_generated_report(conn: psycopg.Connection, resource_type: str, resource_id: str, format_name: str) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT id, resource_type, resource_id, format, path, created_at
        FROM generated_reports
        WHERE resource_type = %s AND resource_id = %s AND format = %s
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (resource_type, resource_id, format_name),
    ).fetchone()
    return dict(row) if row else None


def generated_report(conn: psycopg.Connection, report_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT id, resource_type, resource_id, format, path, created_at
        FROM generated_reports
        WHERE id = %s
        """,
        (report_id,),
    ).fetchone()
    return dict(row) if row else None


def artifact(conn: psycopg.Connection, artifact_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT id, pipeline_id, scan_id, image_ref, kind, format, path, created_at
        FROM artifacts
        WHERE id = %s
        """,
        (artifact_id,),
    ).fetchone()
    return dict(row) if row else None


def cleanup_old_records(conn: psycopg.Connection, days: int) -> dict[str, int]:
    result: dict[str, int] = {}
    tables = [
        ("audit_logs", "created_at"),
        ("generated_reports", "created_at"),
        ("security_findings", "created_at"),
        ("security_jobs", "started_at"),
        ("pipeline_jobs", "created_at"),
    ]
    for table, column in tables:
        row = conn.execute(
            f"DELETE FROM {table} WHERE {column} < now() - (%s || ' days')::interval RETURNING 1",
            (days,),
        ).fetchall()
        result[table] = len(row)
    return result


def upsert_scheduled_image(conn: psycopg.Connection, image_ref: str, interval_minutes: int) -> str:
    schedule_id = str(uuid4())
    row = conn.execute(
        """
        INSERT INTO scheduled_images (id, image_ref, interval_minutes)
        VALUES (%s, %s, %s)
        ON CONFLICT (image_ref)
        DO UPDATE SET interval_minutes = EXCLUDED.interval_minutes, enabled = true
        RETURNING id
        """,
        (schedule_id, image_ref, interval_minutes),
    ).fetchone()
    return str(row["id"])


def due_scheduled_images(conn: psycopg.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT *
        FROM scheduled_images
        WHERE enabled = true
          AND (
            last_enqueued_at IS NULL
            OR last_enqueued_at <= now() - (interval_minutes || ' minutes')::interval
          )
        ORDER BY last_enqueued_at NULLS FIRST, created_at ASC
        """
    ).fetchall()
    return [dict(row) for row in rows]


def mark_scheduled_enqueued(conn: psycopg.Connection, schedule_id: str) -> None:
    conn.execute(
        "UPDATE scheduled_images SET last_enqueued_at = now() WHERE id = %s",
        (schedule_id,),
    )


def pipeline_summary(conn: psycopg.Connection, pipeline_id: str) -> dict[str, Any]:
    pipeline = conn.execute(
        "SELECT * FROM pipeline_runs WHERE id = %s",
        (pipeline_id,),
    ).fetchone()
    scans = conn.execute(
        """
        SELECT id, image_ref, phase, status, report_path, raw_report, critical_count, high_count, medium_count, low_count, unknown_count, started_at, finished_at, error_message
        FROM scan_runs
        WHERE pipeline_id = %s
        ORDER BY started_at
        """,
        (pipeline_id,),
    ).fetchall()
    patches = conn.execute(
        """
        SELECT id, source_image_ref, patched_image_ref, local_image_ref, local_image_id,
               publication_status, published_at, published_digest, status, copa_report_path, started_at, finished_at, error_message
        FROM patch_runs
        WHERE pipeline_id = %s
        ORDER BY started_at
        """,
        (pipeline_id,),
    ).fetchall()
    diffs = conn.execute(
        """
        SELECT id, original_scan_id, patched_scan_id, fixed_count, remaining_count, introduced_count,
               fixed_vulnerabilities, remaining_vulnerabilities, introduced_vulnerabilities,
               created_at
        FROM scan_diffs
        WHERE pipeline_id = %s
        ORDER BY created_at
        """,
        (pipeline_id,),
    ).fetchall()
    policies = conn.execute(
        """
        SELECT id, scan_id, status, rules, violations, created_at
        FROM policy_results
        WHERE pipeline_id = %s
        ORDER BY created_at
        """,
        (pipeline_id,),
    ).fetchall()
    artifacts = conn.execute(
        """
        SELECT id, scan_id, image_ref, kind, format, path, created_at
        FROM artifacts
        WHERE pipeline_id = %s
        ORDER BY created_at
        """,
        (pipeline_id,),
    ).fetchall()
    reports = list_generated_reports(conn, "pipeline", pipeline_id)
    return {
        "pipeline": pipeline,
        "scans": scans,
        "patches": patches,
        "diffs": diffs,
        "policies": policies,
        "artifacts": artifacts,
        "reports": reports,
    }


def record_service_heartbeat(conn: psycopg.Connection, service: str, instance: str) -> None:
    """Record liveness without giving the API access to the Docker daemon."""
    conn.execute(
        """INSERT INTO service_heartbeats(service, instance, last_seen)
           VALUES (%s, %s, now())
           ON CONFLICT (service, instance) DO UPDATE SET last_seen = now()""",
        (service[:80], instance[:150]),
    )


def service_health_summary(conn: psycopg.Connection) -> dict[str, Any]:
    heartbeats = conn.execute(
        """SELECT service, instance, last_seen,
                  EXTRACT(EPOCH FROM (now() - last_seen))::int AS seconds_ago
           FROM service_heartbeats
           WHERE last_seen > now() - interval '24 hours'
           ORDER BY service, last_seen DESC LIMIT 40"""
    ).fetchall()
    queues = conn.execute(
        """SELECT status, count(*)::int AS count FROM pipeline_jobs
           GROUP BY status ORDER BY status"""
    ).fetchall()
    security = conn.execute(
        """SELECT status, count(*)::int AS count FROM security_jobs
           GROUP BY status ORDER BY status"""
    ).fetchall()
    return {
        "database": "connected",
        "heartbeats": [dict(row) for row in heartbeats],
        "pipeline_queue": [dict(row) for row in queues],
        "secret_queue": [dict(row) for row in security],
        "note": "A stale heartbeat may indicate a busy worker; verify with ./appsec status and logs.",
    }

def update_user_admin(
    conn: psycopg.Connection, user_id: str, actor_id: str,
    *, display_name: str | None = None, role: str | None = None,
    disabled: bool | None = None,
) -> dict[str, Any] | None:
    # Lock ALL active admins to prevent concurrent requests removing the last one.
    active_admins = conn.execute(
        "SELECT id FROM users WHERE role='admin' AND disabled=false FOR UPDATE"
    ).fetchall()
    row = conn.execute(
        "SELECT id, username, display_name, role, disabled FROM users WHERE id=%s FOR UPDATE",
        (user_id,),
    ).fetchone()
    if not row:
        return None
    future_role = role if role is not None else row["role"]
    future_disabled = disabled if disabled is not None else row["disabled"]
    if str(user_id) == str(actor_id) and (future_disabled or future_role != "admin"):
        raise ValueError("Administrators cannot disable or demote their own account")
    if row["role"] == "admin" and not row["disabled"] and (
        future_role != "admin" or future_disabled
    ) and len(active_admins) <= 1:
        raise ValueError("At least one active administrator must remain")
    conn.execute("""
        UPDATE users SET display_name=COALESCE(%s, display_name),
          role=COALESCE(%s, role), disabled=COALESCE(%s, disabled)
        WHERE id=%s
    """, (display_name, role, disabled, user_id))
    if future_disabled or future_role != row["role"]:
        conn.execute(
            "UPDATE session_tokens SET revoked_at=now() WHERE user_id=%s AND revoked_at IS NULL",
            (user_id,),
        )
    if future_disabled:
        # Invalidate legacy API keys permanently, even if reenabled later.
        conn.execute("""
            UPDATE users SET api_key_hash=%s, api_key_rotated_at=now(),
                locked_until=NULL, failed_login_count=0 WHERE id=%s
        """, (api_key_hash(secrets.token_urlsafe(48)), user_id))
    return dict(conn.execute("""
        SELECT id, username, display_name, role, disabled, must_change_password
        FROM users WHERE id=%s
    """, (user_id,)).fetchone())


def reset_user_password(conn: psycopg.Connection, user_id: str, password: str) -> bool:
    row = conn.execute("""
        UPDATE users SET password_hash=%s, must_change_password=true,
          failed_login_count=0, locked_until=NULL, password_changed_at=now()
        WHERE id=%s RETURNING id
    """, (password_hash(password), user_id)).fetchone()
    if not row:
        return False
    conn.execute(
        "UPDATE session_tokens SET revoked_at=now() WHERE user_id=%s AND revoked_at IS NULL",
        (user_id,),
    )
    return True


def rotate_user_api_key(conn: psycopg.Connection, user_id: str) -> str | None:
    value = secrets.token_urlsafe(48)
    row = conn.execute("""
        UPDATE users SET api_key_hash=%s, api_key_rotated_at=now()
        WHERE id=%s RETURNING id
    """, (api_key_hash(value), user_id)).fetchone()
    return value if row else None


def revoke_all_sessions(conn: psycopg.Connection, user_id: str) -> int:
    rows = conn.execute(
        """UPDATE session_tokens SET revoked_at=now()
           WHERE user_id=%s AND revoked_at IS NULL RETURNING id""",
        (user_id,),
    ).fetchall()
    return len(rows)


def list_user_sessions(conn: psycopg.Connection, user_id: str) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute("""
        SELECT id, created_at, expires_at, revoked_at
        FROM session_tokens WHERE user_id=%s
        ORDER BY created_at DESC LIMIT 50
    """, (user_id,)).fetchall()]


def list_user_memberships(conn: psycopg.Connection, user_id: str) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute("""
        SELECT t.id AS team_id, t.name AS team_name, tm.role
        FROM team_members tm JOIN teams t ON t.id=tm.team_id
        WHERE tm.user_id=%s ORDER BY t.name
    """, (user_id,)).fetchall()]
