from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from . import db
from .errors import safe_message
from .sanitization import MASK, redact_gitleaks_report, validate_repo_target


def env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def run_command(command: list[str], **options) -> int:
    result = subprocess.run(
        command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=False, **options,
    )
    return result.returncode


def report_name(kind: str, identifier: str, suffix: str = ".json") -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{kind}-{timestamp}-{identifier}{suffix}"


def prepare_repo(target: str, job_id: str, credentials=None, full_history=False) -> Path:
    try:
        target = validate_repo_target(target)
    except ValueError:
        raise RuntimeError("REPO_TARGET: invalid repository target") from None
    base = Path(env("WORKSPACES_DIR", "/workspaces"))
    base.mkdir(parents=True, exist_ok=True)
    dest = base / job_id
    if dest.exists():
        shutil.rmtree(dest)
    exit_code = None
    try:
        with tempfile.TemporaryDirectory(prefix="appsec-git-") as directory:
            helper = Path(directory) / "askpass"
            helper.write_text('#!/bin/sh\ncase "$1" in *sername*) printf "%s\\n" "$APPSEC_GIT_USER";; *) printf "%s\\n" "$APPSEC_GIT_SECRET";; esac\n')
            helper.chmod(0o700)
            environment = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
                           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ASKPASS": str(helper),
                           "LC_ALL": "C", "APPSEC_GIT_USER": credentials[0] if credentials else "",
                           "APPSEC_GIT_SECRET": credentials[1] if credentials else ""}
            for key in list(environment):
                if key.startswith(("GIT_TRACE", "GIT_CONFIG_")) and key not in ("GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL"):
                    environment.pop(key)
            environment.pop("GIT_CURL_VERBOSE", None)
            environment.pop("GIT_SSL_NO_VERIFY", None)
            exit_code = run_command(
                ["git", "-c", "http.followRedirects=false", "-c", "http.sslVerify=true",
                 "-c", "credential.helper=", "-c", "protocol.file.allow=never",
                 "clone"] + ([] if full_history else ["--depth", "1"]) + ["--", target, str(dest)],
                timeout=300 if full_history else 120, env=environment,
            )
        if exit_code:
            raise RuntimeError("GIT_CLONE_FAILED: git clone returned an error")
    except subprocess.TimeoutExpired:
        raise RuntimeError("GIT_CLONE_TIMEOUT: git clone exceeded 120 seconds") from None
    except OSError:
        raise RuntimeError("GIT_CLONE_FAILED: could not start git") from None
    finally:
        if exit_code != 0 and dest.exists():
            shutil.rmtree(dest)
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
            from . import repo_credentials
            with db.connect() as conn:
                credentials = repo_credentials.consume(conn, job_id)
            full_history = profile in ("strict", "release")
            repo_path = prepare_repo(target, job_id, credentials, full_history)
            del credentials
            from . import image_sources
            with db.connect() as conn:
                configured = image_sources.configured_sources(conn)
            scanner = image_sources.runtime_image(env("GITLEAKS_IMAGE", "zricethezav/gitleaks:latest"))
            scan_exit_code = run_command(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--pull=never" if configured is not None else "--pull=missing",
                    "--network", "none",
                    "-v",
                    f"{workspaces_volume}:/scan:ro",
                    "-v",
                    f"{reports_volume}:/reports",
                    scanner,
                    "git" if full_history else "dir",
                    f"/scan/{repo_path.name}",
                    "--report-format",
                    "json",
                    "--report-path",
                    f"/reports/{report_file}",
                    "--redact=100",
                    "--exit-code=17",
                ],
            )
            # 0: no leaks; 17: leaks found (custom exit code). Other codes
            # indicate scanner/runtime failure and must never pass CI.
            if scan_exit_code == 125:
                raise RuntimeError("GITLEAKS_DOCKER: docker run failed before scanner execution")
            if scan_exit_code not in (0, 17):
                raise RuntimeError("GITLEAKS_FAILED: scanner returned an unexpected exit status")
            try:
                raw = redact_gitleaks_report(json.loads(report_path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                raise RuntimeError("GITLEAKS_REPORT: expected a readable JSON report") from None
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
            db.update_security_job_failed(conn, job_id, safe_message(exc, "repository"))
        raise
    finally:
        # Cloned source trees can contain the very secrets we just detected.
        # Never retain an unredacted failed scanner output.
        if report_path.exists() and "raw" not in locals():
            report_path.unlink(missing_ok=True)
        if repo_path is not None and repo_path.exists():
            shutil.rmtree(repo_path)

    return job_id


def run_security_job(kind: str, target: str, requested_by: str | None = None, profile: str = "standard") -> str:
    job_id = str(uuid4())
    with db.connect() as conn:
        db.insert_security_job_started(conn, job_id, kind, target, requested_by, profile)
    return execute_security_job(job_id)
