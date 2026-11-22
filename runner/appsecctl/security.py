from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from . import db
from .sanitization import MASK, redact_gitleaks_report, validate_repo_target


def env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def run_command(command: list[str], allow_failure: bool = False) -> int:
    print("+ " + " ".join(command), flush=True)
    result = subprocess.run(command, check=False)
    if result.returncode != 0 and not allow_failure:
        raise subprocess.CalledProcessError(result.returncode, command)
    return result.returncode


def report_name(kind: str, identifier: str, suffix: str = ".json") -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{kind}-{timestamp}-{identifier}{suffix}"


def prepare_repo(target: str, job_id: str) -> Path:
    base = Path(env("WORKSPACES_DIR", "/workspaces"))
    base.mkdir(parents=True, exist_ok=True)
    dest = base / job_id
    if dest.exists():
        shutil.rmtree(dest)
    run_command(["git", "-c", "http.followRedirects=false", "-c", "protocol.file.allow=never", "clone", "--depth", "1", validate_repo_target(target), str(dest)])
    return dest


def count_findings(findings: list[dict]) -> dict[str, int]:
    counts = {"total": len(findings), "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = (finding.get("severity") or "info").lower()
        if severity in ("critical", "error", "high"):
            counts["high"] += 1
        elif severity in ("warning", "medium"):
            counts["medium"] += 1
        elif severity in ("low",):
            counts["low"] += 1
        else:
            counts["info"] += 1
    return counts


def parse_gitleaks(report: list[dict]) -> list[dict]:
    findings = []
    for item in report or []:
        findings.append(
            {
                "rule_id": item.get("RuleID"),
                "severity": "high",
                "title": item.get("Description") or item.get("RuleID"),
                "description": item.get("Description"),
                "location": f"{item.get('File', '')}:{item.get('StartLine', 1)}",
                "evidence": MASK if item.get("Match") or item.get("Secret") else None,
                "metadata": {
                    "commit": item.get("Commit"),
                    "author": item.get("Author"),
                },
            }
        )
    return findings


def enqueue_security_job(
    kind: str,
    target: str,
    requested_by: str | None = None,
    priority: int = 100,
    profile: str = "standard",
    project_id: str | None = None,
) -> str:
    with db.connect() as conn:
        return db.enqueue_security_job(conn, kind, target, requested_by, priority, profile, project_id)


def execute_security_job(job_id: str) -> str:
    reports_dir = Path(env("REPORTS_DIR", "/reports"))
    reports_volume = env("REPORTS_VOLUME", "appsec_reports")
    workspaces_volume = env("WORKSPACES_VOLUME", "appsec_workspaces")
    reports_dir.mkdir(parents=True, exist_ok=True)

    with db.connect() as conn:
        job = conn.execute("SELECT * FROM security_jobs WHERE id = %s", (job_id,)).fetchone()
    if not job:
        raise RuntimeError(f"security job not found: {job_id}")
    kind = str(job["kind"])
    target = str(job["target"])
    profile = str(job.get("profile") or "standard")

    report_file = report_name(kind, job_id)
    report_path = reports_dir / report_file

    repo_path = None
    try:
        if kind == "secrets":
            repo_path = prepare_repo(target, job_id)
            scan_exit_code = run_command(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{workspaces_volume}:/{workspaces_volume}",
                    "-v",
                    f"{reports_volume}:/reports",
                    env("GITLEAKS_IMAGE", "zricethezav/gitleaks:latest"),
                    "detect",
                    "--source",
                    f"/{workspaces_volume}/{repo_path.name}",
                    "--report-format",
                    "json",
                    "--report-path",
                    f"/reports/{report_file}",
                    "--no-git",
                    "--redact=100",
                    "--exit-code=17",
                ],
                allow_failure=True,
            )
            # 0: no leaks; 17: leaks found (custom exit code). Other codes
            # indicate scanner/runtime failure and must never pass CI.
            if scan_exit_code not in (0, 17):
                raise RuntimeError(f"Gitleaks failed with exit status {scan_exit_code}")
            if not report_path.exists():
                raise RuntimeError("Gitleaks did not generate a report")
            raw = redact_gitleaks_report(json.loads(report_path.read_text(encoding="utf-8")))
            report_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
            findings = parse_gitleaks(raw)
        else:
            raise RuntimeError(f"unsupported security job kind: {kind}")

        counts = count_findings(findings)
        with db.connect() as conn:
            db.update_security_job_success(conn, job_id, str(report_path), raw, counts)
            db.insert_security_findings(conn, job_id, findings)
    except BaseException as exc:
        with db.connect() as conn:
            db.update_security_job_failed(conn, job_id, str(exc))
        raise
    finally:
        # Cloned source trees can contain the very secrets we just detected.
        if repo_path is not None and repo_path.exists():
            shutil.rmtree(repo_path)

    return job_id


def run_security_job(kind: str, target: str, requested_by: str | None = None, profile: str = "standard") -> str:
    job_id = str(uuid4())
    with db.connect() as conn:
        db.insert_security_job_started(conn, job_id, kind, target, requested_by, profile)
    return execute_security_job(job_id)
