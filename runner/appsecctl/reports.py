from __future__ import annotations

import html
import json
import os
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from . import db
from .artifacts import upload_artifact


def reports_dir() -> Path:
    path = Path(os.environ.get("REPORTS_DIR", "/reports"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_html_report(resource_type: str, resource_id: str, payload: dict[str, Any]) -> str:
    ensure_report_ready(resource_type, payload)
    name = (f"report-pipeline-{resource_id}.html" if resource_type == "pipeline"
            else f"report-{resource_type}-{resource_id}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.html")
    path = reports_dir() / name
    title = f"{resource_type.replace('_', ' ').title()} Report"
    document = pipeline_report_html(resource_id, payload) if resource_type == "pipeline" else security_report_html(resource_id, payload)
    path.write_text(document, encoding="utf-8")
    stored_path = upload_artifact(str(path), f"{resource_type}/{resource_id}")
    with db.connect() as conn:
        if resource_type == "pipeline":
            existing = db.latest_generated_report(conn, resource_type, resource_id, "html")
            if existing:
                conn.execute("UPDATE generated_reports SET path=%s, created_at=now() WHERE id=%s",
                             (stored_path, existing["id"]))
                conn.execute("""DELETE FROM generated_reports
                                WHERE resource_type=%s AND resource_id=%s AND format='html' AND id<>%s""",
                             (resource_type, resource_id, existing["id"]))
            else:
                db.insert_generated_report(conn, resource_type, resource_id, "html", stored_path)
        else:
            db.insert_generated_report(conn, resource_type, resource_id, "html", stored_path)
    return stored_path


def ensure_report_ready(resource_type: str, payload: dict[str, Any]) -> None:
    if resource_type == "pipeline":
        status = str(row_dict(payload.get("pipeline")).get("status") or "")
        if status not in ("success", "policy_failed", "failed"):
            raise RuntimeError(f"pipeline report is only available after completion; current status is {status or 'unknown'}")
    if resource_type == "security_job":
        status = str(row_dict(payload.get("job")).get("status") or "")
        if status not in ("success", "failed"):
            raise RuntimeError(f"security job report is only available after completion; current status is {status or 'unknown'}")


def pipeline_report_html(resource_id: str, payload: dict[str, Any]) -> str:
    """One colorful, standalone Before/After report instead of many stage tables."""
    from .consolidated_report import render
    return render(resource_id, payload)


def security_report_html(resource_id: str, payload: dict[str, Any]) -> str:
    job = row_dict(payload.get("job"))
    findings = [row_dict(item) for item in payload.get("findings", [])]
    reports = [row_dict(item) for item in payload.get("reports", [])]
    title = "AppSec Security Job Report"
    body = "\n".join(
        [
            header(title, resource_id),
            section(
                "Job Summary",
                table(
                    [job],
                    [
                        "id",
                        "kind",
                        "target",
                        "status",
                        "finding_count",
                        "high_count",
                        "medium_count",
                        "low_count",
                        "info_count",
                        "started_at",
                        "finished_at",
                    ],
                ),
            ),
            section(
                "Findings",
                table(findings, ["severity", "rule_id", "title", "description", "location", "evidence"]),
            ),
            section("Generated Reports", table(reports, ["id", "format", "created_at"])),
        ]
    )
    return page(title, body)


def page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{esc(title)}</title>
<style>
:root{{color-scheme:light;--bg:#f5f7fb;--panel:#fff;--line:#d8dee9;--text:#172033;--muted:#5d6979;--head:#eef3f8}}
body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;background:var(--bg);color:var(--text)}}
main{{max-width:1280px;margin:0 auto;padding:32px 24px 56px}}
h1{{font-size:26px;margin:0 0 8px}}
h2{{font-size:18px;margin:28px 0 12px}}
.meta{{color:var(--muted);margin-bottom:24px}}
.section{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:18px;margin:18px 0;overflow:auto}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}}
th{{background:var(--head);font-weight:650;white-space:nowrap}}
td{{max-width:520px;word-break:break-word}}
.empty{{color:var(--muted);font-style:italic}}
.severity-critical,.severity-high{{font-weight:700;color:#a61b1b}}
.severity-medium{{font-weight:700;color:#9a5b00}}
.severity-low{{color:#245c2d}}
</style></head><body><main>{body}</main></body></html>"""


def header(title: str, resource_id: str) -> str:
    generated_at = datetime.now(timezone.utc).isoformat()
    return f"<h1>{esc(title)}</h1><div class=\"meta\">Resource ID: {esc(resource_id)} | Generated at: {esc(generated_at)}</div>"


def section(title: str, content: str) -> str:
    return f"<section class=\"section\"><h2>{esc(title)}</h2>{content}</section>"


def table(rows: list[dict[str, Any]], columns: list[str]) -> str:
    if not rows:
        return "<div class=\"empty\">No data</div>"
    head = "".join(f"<th>{esc(label(column))}</th>" for column in columns)
    body_rows = []
    for row in rows:
        cells = "".join(f"<td>{format_value(row.get(column), column)}</td>" for column in columns)
        body_rows.append(f"<tr>{cells}</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"


def vuln_table(rows: list[dict[str, Any]], include_phase: bool = False) -> str:
    columns = [
        "severity",
        "score",
        "vulnerability_id",
        "pkg_name",
        "installed_version",
        "fixed_version",
        "result_class",
        "result_type",
        "target",
        "title",
        "description",
        "primary_url",
    ]
    if include_phase:
        columns = ["phase", "image"] + columns
    return table(rows, columns)


def policy_row(item: dict[str, Any]) -> dict[str, Any]:
    return {
        **item,
        "rules": compact_json(item.get("rules")),
        "violations": compact_json(item.get("violations")),
    }


def paragraph(text: str) -> str:
    return f"<p>{esc(text)}</p>"


def latest_phase(scans: list[dict[str, Any]], phase: str) -> dict[str, Any]:
    candidates = [scan for scan in scans if scan.get("phase") == phase]
    return candidates[-1] if candidates else {}


def scan_total(scan: dict[str, Any]) -> int:
    return sum(int(scan.get(column) or 0) for column in ("critical_count", "high_count", "medium_count", "low_count", "unknown_count"))


def image_metadata_row(scan: dict[str, Any], raw_report: dict[str, Any]) -> dict[str, Any]:
    metadata = row_dict(raw_report.get("Metadata"))
    image_config = row_dict(metadata.get("ImageConfig"))
    os_data = row_dict(metadata.get("OS"))
    image = str(scan.get("image_ref") or metadata.get("Reference") or "")
    return {
        "phase": scan.get("phase"),
        "image": image,
        "version": image_version(image),
        "digest": first_value(metadata.get("RepoDigests")),
        "image_id": metadata.get("ImageID"),
        "size": human_size(metadata.get("Size")),
        "os": "/".join(item for item in [str(os_data.get("Family") or image_config.get("os") or ""), str(os_data.get("Name") or "")] if item),
        "architecture": image_config.get("architecture"),
        "created": image_config.get("created"),
        "layers": len(metadata.get("Layers") or metadata.get("DiffIDs") or []),
    }


def trivy_vulnerability_rows(scan: dict[str, Any], raw_report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for result in raw_report.get("Results", []) or []:
        result_row = row_dict(result)
        target = result_row.get("Target")
        result_class = result_row.get("Class")
        result_type = result_row.get("Type")
        for vuln in result_row.get("Vulnerabilities", []) or []:
            item = row_dict(vuln)
            cvss = best_cvss(item.get("CVSS"))
            rows.append(
                {
                    "phase": scan.get("phase"),
                    "image": scan.get("image_ref"),
                    "target": target,
                    "result_class": result_class,
                    "result_type": result_type,
                    "vulnerability_id": item.get("VulnerabilityID"),
                    "pkg_name": item.get("PkgName"),
                    "installed_version": item.get("InstalledVersion"),
                    "fixed_version": item.get("FixedVersion"),
                    "severity": item.get("Severity"),
                    "score": cvss.get("score"),
                    "vector": cvss.get("vector"),
                    "title": item.get("Title"),
                    "description": item.get("Description"),
                    "primary_url": item.get("PrimaryURL"),
                    "published_date": item.get("PublishedDate"),
                    "last_modified_date": item.get("LastModifiedDate"),
                }
            )
    return rows


def best_cvss(value: Any) -> dict[str, Any]:
    cvss = row_dict(value)
    best = {}
    for source in ("nvd", "redhat", "ghsa", "vendor"):
        data = row_dict(cvss.get(source))
        score = data.get("V3Score") or data.get("V2Score")
        if score is not None:
            return {"score": score, "vector": data.get("V3Vector") or data.get("V2Vector")}
        best = data or best
    return {"score": best.get("V3Score") or best.get("V2Score"), "vector": best.get("V3Vector") or best.get("V2Vector")}


def enrich_vulnerabilities(rows: list[dict[str, Any]], details: dict[tuple[str, str, str], dict[str, Any]]) -> list[dict[str, Any]]:
    enriched = []
    for row in rows:
        row = row_dict(row)
        enriched.append({**row, **details.get(vuln_key(row), {})})
    return enriched


def vuln_key(item: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(item.get("vulnerability_id") or ""),
        str(item.get("pkg_name") or ""),
        str(item.get("target") or ""),
    )


def image_version(image: str) -> str:
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        return last.rsplit(":", 1)[-1]
    if "@" in image:
        return image.split("@", 1)[1]
    return "latest"


def first_value(value: Any) -> str:
    if isinstance(value, list) and value:
        return str(value[0])
    return str(value or "")


def human_size(value: Any) -> str:
    try:
        size = float(value)
    except (TypeError, ValueError):
        return ""
    units = ["B", "KiB", "MiB", "GiB"]
    unit = 0
    while size >= 1024 and unit < len(units) - 1:
        size /= 1024
        unit += 1
    return f"{size:.2f} {units[unit]}"


def row_dict(value: Any) -> dict[str, Any]:
    return dict(value) if value else {}


def json_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [row_dict(item) for item in value]
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return []
        return [row_dict(item) for item in decoded] if isinstance(decoded, list) else []
    return []


def compact_json(value: Any) -> str:
    if value in (None, ""):
        return ""
    return json.dumps(value, ensure_ascii=False, default=str)


def format_value(value: Any, column: str) -> str:
    if value is None:
        return ""
    text = compact_json(value) if isinstance(value, (dict, list)) else str(value)
    if column == "primary_url" and text.startswith(("http://", "https://")):
        return f"<a href=\"{esc(text)}\">{esc(text)}</a>"
    if column == "severity":
        cls = f"severity-{text.lower()}"
        return f"<span class=\"{esc(cls)}\">{esc(text)}</span>"
    return esc(text)


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def label(column: str) -> str:
    return column.replace("_", " ").title()


def security_job_to_sarif(detail: dict[str, Any]) -> dict[str, Any]:
    results = []
    for finding in detail.get("findings", []):
        location = str(finding.get("location") or "unknown:1")
        file_path, _, line = location.rpartition(":")
        try:
            line_number = int(line)
        except ValueError:
            file_path = location
            line_number = 1
        results.append(
            {
                "ruleId": finding.get("rule_id") or "appsec.finding",
                "level": sarif_level(str(finding.get("severity") or "info")),
                "message": {"text": finding.get("description") or finding.get("title") or "Security finding"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": file_path or "unknown"},
                            "region": {"startLine": line_number},
                        }
                    }
                ],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "AppSec Control", "informationUri": "http://127.0.0.1:8080/appsec-api/"}},
                "results": results,
            }
        ],
    }


def sarif_level(severity: str) -> str:
    if severity.lower() in ("critical", "high", "error"):
        return "error"
    if severity.lower() in ("medium", "warning"):
        return "warning"
    return "note"


def write_security_sarif(job_id: str) -> str:
    with db.connect() as conn:
        detail = db.security_job_detail(conn, job_id)
    if not detail:
        raise RuntimeError(f"security job not found: {job_id}")
    path = reports_dir() / f"security-{job_id}.sarif"
    path.write_text(json.dumps(security_job_to_sarif(detail), indent=2, default=str), encoding="utf-8")
    stored_path = upload_artifact(str(path), f"security_job/{job_id}")
    with db.connect() as conn:
        db.insert_generated_report(conn, "security_job", job_id, "sarif", stored_path)
    return stored_path


def notify(event: str, payload: dict[str, Any]) -> None:
    url = os.environ.get("NOTIFY_WEBHOOK_URL", "").strip()
    if not url:
        return
    data = json.dumps({"id": str(uuid4()), "event": event, "payload": payload}, default=str).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        urllib.request.urlopen(request, timeout=int(os.environ.get("NOTIFY_TIMEOUT_SECONDS", "5"))).read()
    except Exception as exc:
        print(f"notification failed: {exc}", flush=True)
