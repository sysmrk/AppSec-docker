"""Optional, strictly read-only MCP adapter for AppSec-docker.

This server never executes a scan, patch, shell command or SQL from the caller.
Only bounded parameterized SELECT queries are exposed. Never expose the
loopback HTTP port publicly without an authenticated TLS/OAuth gateway.
"""
from __future__ import annotations

import argparse
import json
import os
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from mcp.server.mcpserver import MCPServer

mcp = MCPServer("AppSec Image Security (read-only)")


def _uuid(value: str) -> UUID:
    try:
        return UUID(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("a valid UUID identifier is required") from exc


def _limit(value: int) -> int:
    return max(1, min(int(value), 100))


def _fetch(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    url = os.environ.get("APPSEC_MCP_DATABASE_URL", "")
    if not url:
        raise RuntimeError("APPSEC_MCP_DATABASE_URL is missing")
    # PostgreSQL enforces this at transaction level in addition to the
    # restricted SELECT-only tool catalogue. Use a SELECT-only DB role too.
    with psycopg.connect(
        url, row_factory=dict_row, options="-c default_transaction_read_only=on"
    ) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
    return json.loads(json.dumps(rows, default=str))


@mcp.tool()
def get_security_overview() -> dict[str, Any]:
    """Summarize completed and running image pipelines, scans and secret scanning jobs."""
    return {
        "pipeline_statuses": _fetch(
            "SELECT status, count(*)::int AS count FROM pipeline_runs GROUP BY status ORDER BY status"
        ),
        "scan_totals": _fetch(
            """SELECT count(*)::int AS scans,
                      coalesce(sum(critical_count),0)::int AS critical,
                      coalesce(sum(high_count),0)::int AS high,
                      coalesce(sum(medium_count),0)::int AS medium
               FROM scan_runs WHERE status = 'success'"""
        ),
        "secret_scan_statuses": _fetch(
            """SELECT status, count(*)::int AS count, coalesce(sum(high_count),0)::int AS high
               FROM security_jobs GROUP BY status ORDER BY status"""
        ),
    }


@mcp.tool()
def list_pipelines(limit: int = 20) -> dict[str, Any]:
    """List recent container image pipelines and their status. Maximum 100."""
    return {"pipelines": _fetch(
        """SELECT id, project_id, requested_image, status, started_at, finished_at
           FROM pipeline_runs ORDER BY started_at DESC LIMIT %s""",
        (_limit(limit),),
    )}


@mcp.tool()
def get_pipeline(pipeline_id: str) -> dict[str, Any]:
    """Get a pipeline and the status/counts of its scans; no raw reports."""
    pid = _uuid(pipeline_id)
    pipelines = _fetch(
        """SELECT id, project_id, requested_image, status, started_at, finished_at
           FROM pipeline_runs WHERE id = %s""", (pid,)
    )
    if not pipelines:
        return {"error": "pipeline not found"}
    scans = _fetch(
        """SELECT id, image_ref, phase, status, critical_count, high_count,
                  medium_count, low_count, started_at, finished_at
           FROM scan_runs WHERE pipeline_id = %s ORDER BY started_at DESC LIMIT 30""",
        (pid,),
    )
    return {"pipeline": pipelines[0], "scans": scans}


@mcp.tool()
def list_image_vulnerabilities(
    pipeline_id: str, phase: str = "patched", limit: int = 30
) -> dict[str, Any]:
    """Return CVE/package/version findings for original or patched scans, max 100."""
    if phase not in ("original", "patched", "manual"):
        raise ValueError("phase must be original, patched or manual")
    findings = _fetch(
        """SELECT s.id AS scan_id, s.phase, v.vulnerability_id, v.pkg_name,
                  v.installed_version, v.fixed_version, v.severity, v.title, v.primary_url
           FROM scan_runs s JOIN vulnerabilities v ON v.scan_id = s.id
           WHERE s.pipeline_id = %s AND s.phase = %s
           ORDER BY CASE v.severity
                      WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                      WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
                    v.vulnerability_id
           LIMIT %s""",
        (_uuid(pipeline_id), phase, _limit(limit)),
    )
    return {"phase": phase, "findings": findings}


@mcp.tool()
def list_secret_scan_jobs(limit: int = 20) -> dict[str, Any]:
    """Show only metadata and aggregate severity from recent Gitleaks jobs."""
    return {"jobs": _fetch(
        """SELECT id, project_id, target, status, finding_count,
                  high_count, medium_count, started_at, finished_at
           FROM security_jobs ORDER BY started_at DESC LIMIT %s""",
        (_limit(limit),),
    )}


@mcp.tool()
def get_secret_findings(job_id: str, limit: int = 30) -> dict[str, Any]:
    """Return redacted secret finding metadata, never Match/Secret/Line/evidence."""
    sid = _uuid(job_id)
    job = _fetch(
        """SELECT id, project_id, kind, target, status, finding_count, started_at
           FROM security_jobs WHERE id = %s""", (sid,),
    )
    if not job:
        return {"error": "security job not found"}
    findings = _fetch(
        """SELECT id, rule_id, severity, title, description, location, created_at
           FROM security_findings WHERE job_id = %s
           ORDER BY created_at DESC LIMIT %s""",
        (sid, _limit(limit)),
    )
    return {"job": job[0], "findings": findings, "secrets_redacted": True}


@mcp.tool()
def get_policy_results(pipeline_id: str, limit: int = 20) -> dict[str, Any]:
    """Read recent policy decisions for a pipeline without changing any policy."""
    return {"policy_results": _fetch(
        """SELECT id, pipeline_id, scan_id, status, violations, created_at
           FROM policy_results WHERE pipeline_id = %s
           ORDER BY created_at DESC LIMIT %s""",
        (_uuid(pipeline_id), _limit(limit)),
    )}


def main() -> None:
    parser = argparse.ArgumentParser(description="AppSec optional read-only MCP adapter")
    parser.add_argument("--transport", choices=("stdio", "http"), default="http")
    parser.add_argument("--port", type=int, default=int(os.environ.get("APPSEC_MCP_PORT", "8090")))
    args = parser.parse_args()
    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(
            transport="streamable-http", host="0.0.0.0", port=args.port,
            stateless_http=True, json_response=True,
        )


if __name__ == "__main__":
    main()
