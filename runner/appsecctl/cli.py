from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from alembic import command as alembic_command
from alembic.config import Config as AlembicConfig

from . import db, policy
from .reports import write_html_report, write_security_sarif
from .security import enqueue_security_job, run_security_job


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def run_command(command: list[str]) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, check=True)


def report_name(prefix: str, identifier: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}-{timestamp}-{identifier}.json"


def parse_trivy_report(report: dict) -> tuple[dict[str, int], list[dict]]:
    counts = {severity: 0 for severity in SEVERITIES}
    vulnerabilities = []

    for result in report.get("Results", []) or []:
        target = result.get("Target")
        for vuln in result.get("Vulnerabilities", []) or []:
            severity = (vuln.get("Severity") or "UNKNOWN").upper()
            if severity not in counts:
                severity = "UNKNOWN"
            counts[severity] += 1
            vulnerabilities.append(
                {
                    "target": target,
                    "vulnerability_id": vuln.get("VulnerabilityID"),
                    "pkg_name": vuln.get("PkgName"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "severity": severity,
                    "title": vuln.get("Title"),
                    "primary_url": vuln.get("PrimaryURL"),
                }
            )

    return counts, vulnerabilities


def vuln_key(item: dict) -> tuple[str, str, str]:
    return (
        str(item.get("vulnerability_id") or ""),
        str(item.get("pkg_name") or ""),
        str(item.get("target") or ""),
    )


def docker_base() -> list[str]:
    return ["docker", "run", "--rm", "--network", env("TOOL_NETWORK", "appsec-net")]


def scan_image(image_ref: str, phase: str, pipeline_id: str | None = None) -> str:
    scan_id = str(uuid4())
    reports_dir = Path(env("REPORTS_DIR", "/reports"))
    reports_volume = env("REPORTS_VOLUME", "appsec_reports")
    trivy_cache_volume = env("TRIVY_CACHE_VOLUME", "appsec_trivy_cache")
    trivy_image = env("TRIVY_IMAGE", "aquasec/trivy:latest")
    trivy_db_repository = env("TRIVY_DB_REPOSITORY", "ghcr.io/aquasecurity/trivy-db:2")
    report_file = report_name(f"trivy-{phase}", scan_id)
    report_path = reports_dir / report_file
    container_report_path = f"/reports/{report_file}"

    with db.connect() as conn:
        image_id = db.get_or_create_image(conn, image_ref)
        db.insert_scan_started(conn, scan_id, pipeline_id, image_id, image_ref, phase)

    command = docker_base() + [
        "-e",
        f"TRIVY_DB_REPOSITORY={trivy_db_repository}",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "-v",
        f"{reports_volume}:/reports",
        "-v",
        f"{trivy_cache_volume}:/root/.cache/trivy",
        trivy_image,
        "image",
        "--scanners",
        "vuln",
        "--pkg-types",
        "os",
        "--ignore-unfixed",
        "--format",
        "json",
        "--output",
        container_report_path,
        image_ref,
    ]

    try:
        run_command(command)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        counts, vulnerabilities = parse_trivy_report(report)
        with db.connect() as conn:
            db.update_scan_success(conn, scan_id, str(report_path), report, counts)
            db.insert_vulnerabilities(conn, scan_id, vulnerabilities)
            db.insert_artifact(conn, pipeline_id, scan_id, image_ref, "trivy-report", "json", str(report_path))
    except BaseException as exc:
        with db.connect() as conn:
            db.update_scan_failed(conn, scan_id, str(exc))
        raise

    print(json.dumps({"scan_id": scan_id, "image": image_ref, "phase": phase}, indent=2))
    return scan_id


def generate_sbom(image_ref: str, phase: str, scan_id: str, pipeline_id: str | None = None) -> str:
    artifact_id = str(uuid4())
    reports_dir = Path(env("REPORTS_DIR", "/reports"))
    reports_volume = env("REPORTS_VOLUME", "appsec_reports")
    trivy_cache_volume = env("TRIVY_CACHE_VOLUME", "appsec_trivy_cache")
    trivy_image = env("TRIVY_IMAGE", "aquasec/trivy:latest")
    trivy_db_repository = env("TRIVY_DB_REPOSITORY", "ghcr.io/aquasecurity/trivy-db:2")
    sbom_file = report_name(f"sbom-{phase}", artifact_id).replace(".json", ".cdx.json")
    sbom_path = reports_dir / sbom_file
    container_sbom_path = f"/reports/{sbom_file}"

    command = docker_base() + [
        "-e",
        f"TRIVY_DB_REPOSITORY={trivy_db_repository}",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "-v",
        f"{reports_volume}:/reports",
        "-v",
        f"{trivy_cache_volume}:/root/.cache/trivy",
        trivy_image,
        "image",
        "--format",
        "cyclonedx",
        "--output",
        container_sbom_path,
        image_ref,
    ]

    run_command(command)
    with db.connect() as conn:
        db.insert_artifact(conn, pipeline_id, scan_id, image_ref, "sbom", "cyclonedx-json", str(sbom_path))
    return str(sbom_path)


def patched_image_ref(source_image_ref: str, patch_id: str) -> str:
    registry = env("REGISTRY_HOST", "localhost:8081").rstrip("/")
    repository = env("PATCHED_REPOSITORY", "library/appsec-patched").strip("/")
    safe_name = (
        source_image_ref.replace("://", "-")
        .replace("/", "-")
        .replace(":", "-")
        .replace("@", "-")
    )
    return f"{registry}/{repository}/{safe_name}:patched-{patch_id[:12]}"


def source_repository(image_ref: str) -> str:
    if "@" in image_ref:
        return image_ref.split("@", 1)[0]
    last_segment = image_ref.rsplit("/", 1)[-1]
    if ":" in last_segment:
        return image_ref.rsplit(":", 1)[0]
    return image_ref


def patch_from_scan(scan_id: str) -> tuple[str, str]:
    patch_id = str(uuid4())

    with db.connect() as conn:
        scan = db.get_scan(conn, scan_id)
        if scan["status"] != "success":
            raise RuntimeError(f"scan {scan_id} is not successful")
        source_image_ref = scan["image_ref"]
        pipeline_id = scan["pipeline_id"]
        if pipeline_id is None:
            pipeline_id = db.create_pipeline(conn, str(scan["image_id"]), source_image_ref)
            db.attach_scan_to_pipeline(conn, scan_id, pipeline_id)
        pipeline_id = str(pipeline_id)
        report_path = Path(scan["report_path"])
        patched_ref = patched_image_ref(source_image_ref, patch_id)
        db.insert_patch_started(conn, patch_id, pipeline_id, scan_id, source_image_ref, patched_ref)

    patch_tag = f"patched-{patch_id[:12]}"
    local_patched_ref = f"{source_repository(source_image_ref)}:{patch_tag}"

    command = [
        "copa",
        "patch",
        "-i",
        source_image_ref,
        "-r",
        str(report_path),
        "-t",
        patch_tag,
        "--addr",
        f"docker-container://{env('BUILDKIT_CONTAINER', 'appsec-buildkit')}",
        "--timeout",
        env("COPA_TIMEOUT", "30m"),
    ]

    try:
        run_command(command)
        run_command(["docker", "tag", local_patched_ref, patched_ref])
        run_command(["docker", "push", patched_ref])
        with db.connect() as conn:
            db.update_patch_success(conn, patch_id, None)
    except BaseException as exc:
        with db.connect() as conn:
            db.update_patch_failed(conn, patch_id, str(exc))
        raise

    print(json.dumps({"patch_id": patch_id, "patched_image": patched_ref}, indent=2))
    return patch_id, patched_ref


def create_diff(pipeline_id: str, original_scan_id: str, patched_scan_id: str) -> str:
    with db.connect() as conn:
        original = db.vulnerabilities_for_scan(conn, original_scan_id)
        patched = db.vulnerabilities_for_scan(conn, patched_scan_id)

        original_by_key = {vuln_key(item): item for item in original}
        patched_by_key = {vuln_key(item): item for item in patched}

        fixed = [original_by_key[key] for key in sorted(original_by_key.keys() - patched_by_key.keys())]
        remaining = [patched_by_key[key] for key in sorted(original_by_key.keys() & patched_by_key.keys())]
        introduced = [patched_by_key[key] for key in sorted(patched_by_key.keys() - original_by_key.keys())]

        diff_id = db.insert_scan_diff(
            conn,
            pipeline_id,
            original_scan_id,
            patched_scan_id,
            fixed,
            remaining,
            introduced,
        )

    print(
        json.dumps(
            {
                "diff_id": diff_id,
                "fixed": len(fixed),
                "remaining": len(remaining),
                "introduced": len(introduced),
            },
            indent=2,
        )
    )
    return diff_id


def evaluate_policy(pipeline_id: str, scan_id: str, project_id: str | None = None) -> str:
    with db.connect() as conn:
        scan = db.get_scan(conn, scan_id)
        rules_from_db = db.active_policy_rules(conn, project_id)
        status, rules, violations = policy.evaluate(scan, rules_from_db)
        db.insert_policy_result(conn, pipeline_id, scan_id, status, rules, violations)

    print(json.dumps({"policy": status, "violations": violations}, indent=2))
    return status


def run_pipeline(image_ref: str, project_id: str | None = None, mode: str = "scan") -> str:
    """Run a safe scan-only workflow unless patch/push is explicitly requested."""
    if mode not in ("scan", "patch"):
        raise ValueError("mode must be scan or patch")
    with db.connect() as conn:
        image_id = db.get_or_create_image(conn, image_ref)
        pipeline_id = db.create_pipeline(conn, image_id, image_ref, project_id)

    try:
        original_scan_id = scan_image(image_ref, "original", pipeline_id)
        generate_sbom(image_ref, "original", original_scan_id, pipeline_id)
        policy_scan_id = original_scan_id
        if mode == "patch":
            _, patched_ref = patch_from_scan(original_scan_id)
            patched_scan_id = scan_image(patched_ref, "patched", pipeline_id)
            generate_sbom(patched_ref, "patched", patched_scan_id, pipeline_id)
            create_diff(pipeline_id, original_scan_id, patched_scan_id)
            policy_scan_id = patched_scan_id
        policy_status = evaluate_policy(pipeline_id, policy_scan_id, project_id)
        with db.connect() as conn:
            db.finish_pipeline(conn, pipeline_id, "success" if policy_status == "passed" else "policy_failed")
    except BaseException as exc:
        with db.connect() as conn:
            db.finish_pipeline(conn, pipeline_id, "failed", str(exc))
        write_pipeline_report_if_ready(pipeline_id)
        raise

    write_pipeline_report_if_ready(pipeline_id)
    print_summary(pipeline_id)
    return pipeline_id


def write_pipeline_report_if_ready(pipeline_id: str) -> None:
    with db.connect() as conn:
        summary = db.pipeline_summary(conn, pipeline_id)
    try:
        write_html_report("pipeline", pipeline_id, summary)
    except RuntimeError:
        raise
    except BaseException as exc:
        print(f"report generation failed for pipeline {pipeline_id}: {exc}", file=sys.stderr, flush=True)


def print_summary(pipeline_id: str) -> None:
    with db.connect() as conn:
        summary = db.pipeline_summary(conn, pipeline_id)
    print(json.dumps(summary, indent=2, default=str))


def ci_image(image_ref: str, mode: str = "scan") -> int:
    pipeline_id = run_pipeline(image_ref, mode=mode)
    with db.connect() as conn:
        summary = db.pipeline_summary(conn, pipeline_id)
    status = summary["pipeline"]["status"]
    print(json.dumps({"pipeline_id": pipeline_id, "status": status}, indent=2))
    return 0 if status == "success" else 1


def ci_security(kind: str, target: str, profile: str) -> int:
    job_id = run_security_job(kind, target, profile=profile)
    with db.connect() as conn:
        detail = db.security_job_detail(conn, job_id)
    job = detail["job"] if detail else {}
    write_security_sarif(job_id)
    print(json.dumps({"security_job_id": job_id, "status": job.get("status"), "high": job.get("high_count", 0)}, indent=2, default=str))
    return 1 if job.get("status") != "success" or int(job.get("high_count") or 0) > int(env("CI_MAX_HIGH", "0")) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="appsecctl")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init-db")
    subparsers.add_parser("migrate")

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("image")
    scan_parser.add_argument("--phase", choices=("original", "patched", "manual"), default="manual")
    scan_parser.add_argument("--pipeline-id")

    patch_parser = subparsers.add_parser("patch")
    patch_parser.add_argument("--scan-id", required=True)

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("image")
    run_parser.add_argument("--patch", action="store_true", help="Explicitly patch and push after scanning (advanced)")

    enqueue_parser = subparsers.add_parser("enqueue")
    enqueue_parser.add_argument("image")
    enqueue_parser.add_argument("--priority", type=int, default=100)
    enqueue_parser.add_argument("--patch", action="store_true", help="Explicitly enable patch and push")

    jobs_parser = subparsers.add_parser("jobs")
    jobs_parser.add_argument("--limit", type=int, default=20)

    schedule_parser = subparsers.add_parser("schedule")
    schedule_parser.add_argument("image")
    schedule_parser.add_argument("--interval-minutes", type=int, default=1440)

    security_parser = subparsers.add_parser("security")
    security_parser.add_argument("kind", choices=("secrets",))
    security_parser.add_argument("target")
    security_parser.add_argument("--async", dest="async_mode", action="store_true")
    security_parser.add_argument("--profile", choices=("quick", "standard", "strict", "release"), default="standard")

    ci_parser = subparsers.add_parser("ci")
    ci_subparsers = ci_parser.add_subparsers(dest="ci_command", required=True)
    ci_image_parser = ci_subparsers.add_parser("image")
    ci_image_parser.add_argument("image")
    ci_image_parser.add_argument("--patch", action="store_true", help="Patch/push explicitly")
    ci_security_parser = ci_subparsers.add_parser("security")
    ci_security_parser.add_argument("kind", choices=("secrets",))
    ci_security_parser.add_argument("target")
    ci_security_parser.add_argument("--profile", choices=("quick", "standard", "strict", "release"), default="standard")

    report_parser = subparsers.add_parser("report")
    report_parser.add_argument("resource_type", choices=("pipeline", "security_job"))
    report_parser.add_argument("resource_id")
    report_parser.add_argument("--format", choices=("html", "sarif"), default="html")

    cleanup_parser = subparsers.add_parser("cleanup")
    cleanup_parser.add_argument("--days", type=int, default=int(env("RETENTION_DAYS", "30")))

    summary_parser = subparsers.add_parser("summary")
    summary_parser.add_argument("--pipeline-id", required=True)

    args = parser.parse_args(argv)

    if args.command == "init-db":
        db.init_schema()
        print("database schema is ready")
        return 0
    if args.command == "migrate":
        config = AlembicConfig("alembic.ini")
        alembic_command.upgrade(config, "head")
        with db.connect() as conn:
            db.ensure_admin_user(conn)
        print("database migrations are ready")
        return 0
    if args.command == "scan":
        scan_image(args.image, args.phase, args.pipeline_id)
        return 0
    if args.command == "patch":
        patch_from_scan(args.scan_id)
        return 0
    if args.command == "run":
        run_pipeline(args.image, mode="patch" if args.patch else "scan")
        return 0
    if args.command == "enqueue":
        with db.connect() as conn:
            job_id = db.enqueue_pipeline(conn, args.image, args.priority, mode="patch" if args.patch else "scan")
        print(json.dumps({"job_id": job_id, "image": args.image}, indent=2))
        return 0
    if args.command == "jobs":
        with db.connect() as conn:
            jobs = db.list_jobs(conn, args.limit)
        print(json.dumps(jobs, indent=2, default=str))
        return 0
    if args.command == "schedule":
        with db.connect() as conn:
            schedule_id = db.upsert_scheduled_image(conn, args.image, args.interval_minutes)
        print(json.dumps({"schedule_id": schedule_id, "image": args.image}, indent=2))
        return 0
    if args.command == "security":
        if args.async_mode:
            job_id = enqueue_security_job(args.kind, args.target, profile=args.profile)
            print(json.dumps({"security_job_id": job_id, "kind": args.kind, "target": args.target, "status": "queued"}, indent=2))
            return 0
        job_id = run_security_job(args.kind, args.target, profile=args.profile)
        print(json.dumps({"security_job_id": job_id, "kind": args.kind, "target": args.target}, indent=2))
        return 0
    if args.command == "ci":
        if args.ci_command == "image":
            return ci_image(args.image, mode="patch" if args.patch else "scan")
        if args.ci_command == "security":
            return ci_security(args.kind, args.target, args.profile)
    if args.command == "report":
        with db.connect() as conn:
            payload = db.pipeline_summary(conn, args.resource_id) if args.resource_type == "pipeline" else db.security_job_detail(conn, args.resource_id)
        if not payload:
            raise RuntimeError(f"{args.resource_type} not found: {args.resource_id}")
        if args.format == "sarif":
            if args.resource_type != "security_job":
                raise RuntimeError("SARIF is only available for security_job")
            path = write_security_sarif(args.resource_id)
        else:
            path = write_html_report(args.resource_type, args.resource_id, payload)
        print(json.dumps({"path": path}, indent=2))
        return 0
    if args.command == "cleanup":
        with db.connect() as conn:
            result = db.cleanup_old_records(conn, args.days)
        print(json.dumps({"days": args.days, "deleted": result}, indent=2))
        return 0
    if args.command == "summary":
        print_summary(args.pipeline_id)
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
