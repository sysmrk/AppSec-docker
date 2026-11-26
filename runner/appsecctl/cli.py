from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from alembic import command as alembic_command
from alembic.config import Config as AlembicConfig

from . import db, policy, image_sources, patch_sources, scan_evidence, tool_updates, remediation_audit
from .errors import safe_message, safe_detail
from . import job_watch
from .reports import write_html_report, write_security_sarif
from .security import enqueue_security_job, run_security_job


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def run_command(command: list[str], *, capture_errors: bool = False, environment: dict[str, str] | None = None,
                timeout: int | None = None) -> None:
    job_watch.checkpoint()
    print("+ " + " ".join(command), flush=True)
    if capture_errors and job_watch.CURRENT.get() is not None:
        try:
            job_watch.capture_stderr(command,environment,timeout)
        except BaseException:
            job_watch.emit("tool_failed")
            raise
        job_watch.emit("done")
    else:
        subprocess.run(command, check=True, stderr=subprocess.PIPE if capture_errors else None,
                       text=capture_errors, env=environment, timeout=timeout)
    job_watch.checkpoint()


def timeout_seconds(name: str, default: int) -> int:
    try:
        value = int(env(name, str(default)))
        if not 1 <= value <= 86400:
            raise ValueError()
        return value
    except ValueError:
        raise RuntimeError("Invalid timeout configuration: " + name) from None


def job_watch_stop_type():
    from .workflow_control import StopRequested
    return StopRequested


def run_trivy_command(command: list[str], stage: str, timeout: int) -> None:
    """Bound Docker client execution and remove only this scanner on timeout."""
    name = "appsec-trivy-" + uuid4().hex
    command = command[:2] + ["--name", name, "--label", "appsec.managed=trivy"] + command[2:]
    started = time.monotonic()
    job_watch.emit("sbom" if stage.startswith("sbom") else "db" if "db" in stage else "scan")
    print(f"SCAN_STAGE_START stage={stage} container={name} timeout={timeout}s", flush=True)
    try:
        run_command(command, capture_errors=True, timeout=timeout)
    except (subprocess.TimeoutExpired, job_watch_stop_type()) as exc:
        try:
            removed = subprocess.run(["docker", "rm", "-f", name], capture_output=True,
                                     text=True, timeout=30, check=False)
            if removed.returncode and "no such container" not in (removed.stderr or "").lower():
                print(f"SCAN_CLEANUP_FAILED container={name}; inspect manually", flush=True)
        except (OSError, subprocess.SubprocessError):
            print(f"SCAN_CLEANUP_FAILED container={name}; inspect manually", flush=True)
        if not isinstance(exc,subprocess.TimeoutExpired):
            raise
        raise RuntimeError(f"SCAN_STAGE_TIMEOUT: {stage} exceeded {timeout}s; scanner container {name}") from None
    except subprocess.CalledProcessError as exc:
        print(f"SCAN_STAGE_FAILED stage={stage} reason={safe_detail(exc.stderr)}", flush=True)
        raise
    else:
        print(f"SCAN_STAGE_DONE stage={stage} seconds={time.monotonic()-started:.1f}", flush=True)


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
        scan_evidence.stable_target(str(item.get("target") or "")),
    )


def docker_base() -> list[str]:
    return ["docker", "run", "--rm", "--network", env("TOOL_NETWORK", "appsec-net")]


def trivy_database_options(sources=None) -> list[str]:
    db_refs = image_sources.artifact_repositories(sources, env("TRIVY_DB_REPOSITORY", "ghcr.io/aquasecurity/trivy-db:2"))
    java_refs = image_sources.artifact_repositories(sources, env("TRIVY_JAVA_DB_REPOSITORY", "ghcr.io/aquasecurity/trivy-java-db:1"))
    return ["-e", f"TRIVY_DB_REPOSITORY={db_refs}", "-e", f"TRIVY_JAVA_DB_REPOSITORY={java_refs}"]


def trivy_metadata_fresh(metadata, now=None):
    """Validate repository content, not the time it happened to be downloaded."""
    try:
        now=now or datetime.now(timezone.utc)
        updated=datetime.fromisoformat(metadata["UpdatedAt"].replace("Z","+00:00"))
        next_update=datetime.fromisoformat(metadata["NextUpdate"].replace("Z","+00:00"))
        return updated <= now < next_update and updated < next_update
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


def trivy_cache_metadata(image, cache, java=False):
    path="/cache/"+("java-db" if java else "db")+"/metadata.json"
    cmd=["docker","run","--rm","--pull=never","--network","none","--user","0:0",
         "-v",cache+":/cache:ro","--entrypoint","/bin/sh",image,"-c",'cat "$1"',"metadata",path]
    try:
        result=subprocess.run(cmd,check=True,capture_output=True,text=True,timeout=30)
        return json.loads(result.stdout)
    except (OSError,subprocess.SubprocessError,ValueError):
        return {}


def invalidate_trivy_metadata(image, cache, java=False):
    # Remove only the stale metadata marker, not the DB or unrelated cache.
    # Trivy must download again rather than accepting its recent-download TTL.
    path="/cache/"+("java-db" if java else "db")+"/metadata.json"
    subprocess.run(["docker","run","--rm","--pull=never","--network","none","--user","0:0",
                    "-v",cache+":/cache","--entrypoint","/bin/sh",image,"-ec",'rm -f -- "$1"',"metadata",path],
                   check=True,timeout=30)


def prepare_trivy_database(trivy_image: str, repositories: str, *, java: bool = False) -> None:
    """Try one approved OCI artifact repository at a time, including HTTP 403/404.
    
    Reject expired metadata even after a successful download. The next source
    must be tried with the stale metadata invalidated. No stale-cache fallback.
    """
    flag = "--java-db-repository" if java else "--db-repository"
    download = "--download-java-db-only" if java else "--download-db-only"
    stage = "java" if java else "vulnerability"
    cache = env("TRIVY_CACHE_VOLUME", "appsec_trivy_cache")
    attempts = []
    if not trivy_metadata_fresh(trivy_cache_metadata(trivy_image,cache,java)):
        invalidate_trivy_metadata(trivy_image,cache,java)
    for ref in repositories.split(","):
        cmd = docker_base() + ["--pull=never", "-v", f"{cache}:/root/.cache/trivy",
                               trivy_image, "image", download, flag, ref]
        try:
            run_trivy_command(cmd, f"trivy-{stage}-db", timeout_seconds("APPSEC_TRIVY_DB_TIMEOUT_SECONDS", 180))
            if trivy_metadata_fresh(trivy_cache_metadata(trivy_image,cache,java)):
                print(f"TRIVY_DB_READY kind={stage} repository={ref} (verified fresh cache or download)", flush=True)
                return
            reason="Database metadata expired or invalid"
            job_watch.emit("db_stale")
            invalidate_trivy_metadata(trivy_image,cache,java)
        except subprocess.CalledProcessError as exc:
            reason = safe_detail(exc.stderr)
        except OSError as exc:
            reason = type(exc).__name__
        except RuntimeError as exc:
            if not str(exc).startswith("SCAN_STAGE_TIMEOUT:"):
                raise
            reason = str(exc)
        attempts.append(f"{ref}: {reason}")
        print(f"TRIVY_DB_SOURCE_FAILED kind={stage} repository={ref} reason={reason}", flush=True)
    code = "TRIVY_JAVA_DB" if java else "TRIVY_DB"
    raise RuntimeError(code + ": All approved database repositories failed: " + "; ".join(attempts)[:1200])


def trivy_runtime() -> tuple[str, list[str], list[str]]:
    with db.connect() as conn:
        sources = image_sources.configured_sources(conn)
        active_version = tool_updates.active(conn, "trivy")
        trivy_image = tool_updates.image_ref("trivy", active_version)
    if sources is None and not active_version:
        # Legacy installations previously let docker run pull the scanner.
        # Keep that behavior, but do not bypass DB freshness validation.
        if subprocess.run(["docker","image","inspect",trivy_image],stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL,timeout=30).returncode:
            run_command(["docker","pull",trivy_image],capture_errors=True,timeout=300)
        resolved=trivy_image
    else:
        resolved = tool_updates.resolve_scanner("trivy", trivy_image, sources, active_version)
    options = trivy_database_options(sources)
    db_refs = image_sources.artifact_repositories(sources, env("TRIVY_DB_REPOSITORY", "ghcr.io/aquasecurity/trivy-db:2"))
    prepare_trivy_database(resolved, db_refs)
    # The scan must not start another vulnerability DB download from defaults.
    options += ["-e", "TRIVY_SKIP_DB_UPDATE=true"]
    if env("APPSEC_PREFETCH_JAVA_DB", "false").lower() in ("1", "true", "yes"):
        java_refs = image_sources.artifact_repositories(sources, env("TRIVY_JAVA_DB_REPOSITORY", "ghcr.io/aquasecurity/trivy-java-db:1"))
        prepare_trivy_database(resolved, java_refs, java=True)
        options += ["-e", "TRIVY_SKIP_JAVA_DB_UPDATE=true"]
    return resolved, ["--pull=never"], options


def scan_image(image_ref: str, phase: str, pipeline_id: str | None = None) -> str:
    scan_id = str(uuid4())
    reports_dir = Path(env("REPORTS_DIR", "/reports"))
    reports_volume = env("REPORTS_VOLUME", "appsec_reports")
    trivy_cache_volume = env("TRIVY_CACHE_VOLUME", "appsec_trivy_cache")
    report_file = report_name(f"trivy-{phase}", scan_id)
    report_path = reports_dir / report_file
    container_report_path = f"/reports/{report_file}"

    with db.connect() as conn:
        image_id = db.get_or_create_image(conn, image_ref)
        db.insert_scan_started(conn, scan_id, pipeline_id, image_id, image_ref, phase)

    try:
        expected_id = scan_evidence.local_image_id(image_ref)
        trivy_image, pull_options, database_options = trivy_runtime()
        command = docker_base() + pull_options + database_options + [
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "-v",
        f"{reports_volume}:/reports",
        "-v",
        f"{trivy_cache_volume}:/root/.cache/trivy",
        trivy_image,
        "image",
        "--image-src", "docker",
        "--scanners",
        "vuln",
        "--pkg-types",
        "os,library",
        "--list-all-pkgs",
        "--ignore-unfixed=false",
        "--format",
        "json",
        "--output",
        container_report_path,
        image_ref,
        ]

        run_trivy_command(command, f"vulnerability-scan-{phase}", timeout_seconds("APPSEC_TRIVY_SCAN_TIMEOUT_SECONDS", 900))
        report = json.loads(report_path.read_text(encoding="utf-8"))
        scan_evidence.validate_report(report, expected_id)
        if scan_evidence.local_image_id(image_ref) != expected_id:
            raise RuntimeError("SCAN_EVIDENCE_INVALID: Image reference changed during scan")
        report["_appsec"] = {"scope": "os,library; all fix statuses", "image_id": expected_id,
                             "verified": True,
                             "os_package_count": sum(len(t.get("Packages") or []) for t in report["Results"] if t.get("Class") == "os-pkgs"),
                             "application_package_count": sum(len(t.get("Packages") or []) for t in report["Results"] if t.get("Class") == "lang-pkgs")}
        scanner_version, scanner_info = tool_updates.scanner_version(trivy_image, cache=True)
        report["_appsec"].update({"trivy_version": scanner_version, "trivy_info": scanner_info,
                                  "scanner_image": trivy_image,
                                  "registry_digests": (report.get("Metadata") or {}).get("RepoDigests") or []})
        counts, vulnerabilities = parse_trivy_report(report)
        job_watch.emit("verified",len(vulnerabilities))
        print(f"SCAN_VERIFIED phase={phase} scan_id={scan_id} image_id={expected_id} findings={len(vulnerabilities)}", flush=True)
        with db.connect() as conn:
            db.update_scan_success(conn, scan_id, str(report_path), report, counts)
            db.insert_vulnerabilities(conn, scan_id, vulnerabilities)
            db.insert_artifact(conn, pipeline_id, scan_id, image_ref, "trivy-report", "json", str(report_path))
    except BaseException as exc:
        with db.connect() as conn:
            db.update_scan_failed(conn, scan_id, safe_message(exc, 'scan'))
        raise

    print(json.dumps({"scan_id": scan_id, "image": image_ref, "phase": phase}, indent=2))
    return scan_id


def generate_sbom(image_ref: str, phase: str, scan_id: str, pipeline_id: str | None = None) -> str:
    artifact_id = str(uuid4())
    reports_dir = Path(env("REPORTS_DIR", "/reports"))
    reports_volume = env("REPORTS_VOLUME", "appsec_reports")
    trivy_cache_volume = env("TRIVY_CACHE_VOLUME", "appsec_trivy_cache")
    trivy_image, pull_options, database_options = trivy_runtime()
    sbom_file = report_name(f"sbom-{phase}", artifact_id).replace(".json", ".cdx.json")
    sbom_path = reports_dir / sbom_file
    container_sbom_path = f"/reports/{sbom_file}"

    command = docker_base() + pull_options + database_options + [
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "-v",
        f"{reports_volume}:/reports",
        "-v",
        f"{trivy_cache_volume}:/root/.cache/trivy",
        trivy_image,
        "image",
        "--image-src", "docker",
        "--format",
        "cyclonedx",
        "--output",
        container_sbom_path,
        image_ref,
    ]

    expected_id = scan_evidence.local_image_id(image_ref)
    run_trivy_command(command, f"sbom-{phase}", timeout_seconds("APPSEC_SBOM_TIMEOUT_SECONDS", 600))
    document = json.loads(sbom_path.read_text(encoding="utf-8"))
    if document.get("bomFormat") != "CycloneDX" or not isinstance(document.get("metadata"), dict):
        raise RuntimeError("SCAN_EVIDENCE_INVALID: SBOM is missing valid CycloneDX metadata")
    if scan_evidence.local_image_id(image_ref) != expected_id:
        raise RuntimeError("SCAN_EVIDENCE_INVALID: Image reference changed during SBOM generation")
    with db.connect() as conn:
        scan = db.get_scan(conn, scan_id)
        if (scan.get("raw_report") or {}).get("_appsec", {}).get("image_id") != expected_id:
            raise RuntimeError("SCAN_EVIDENCE_INVALID: SBOM image differs from verified scan")
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


def patch_from_scan(scan_id: str, *, automatic=False) -> tuple[str, str]:
    patch_id = str(uuid4())

    with db.connect() as conn:
        scan = db.get_scan(conn, scan_id)
        if scan["status"] != "success":
            raise RuntimeError(f"scan {scan_id} is not successful")
        source_image_ref = scan["image_ref"]
        original_report = scan.get("raw_report") or {}
        expected_id = (original_report.get("_appsec") or {}).get("image_id")
        if not expected_id or scan_evidence.local_image_id(source_image_ref) != expected_id:
            raise RuntimeError("SCAN_EVIDENCE_INVALID: Original image is not verified or its tag changed; create a new scan")
        eligibility = scan_evidence.patch_eligibility(scan)
        if eligibility["code"] == "SCAN_EVIDENCE_INVALID":
            raise RuntimeError("SCAN_EVIDENCE_INVALID: Original scan evidence is incomplete")
        # Preflight before creating a patch run, touching BuildKit or preparing any image.
        strategy = scan_evidence.copa_strategy(eligibility, automatic=automatic)
        filtered_report = scan_evidence.copa_report(original_report) if strategy=="targeted" else None
        if strategy=="targeted" and not eligibility["eligible"]:
            raise scan_evidence.NoFixableOS("NO_FIXABLE_OS: No known OS fixes for targeted Copa")
        from . import optimization
        mirrors=optimization.mirrors(conn) if automatic else []
        pipeline_id = scan["pipeline_id"]
        if pipeline_id is None:
            pipeline_id = db.create_pipeline(conn, str(scan["image_id"]), source_image_ref)
            db.attach_scan_to_pipeline(conn, scan_id, pipeline_id)
        pipeline_id = str(pipeline_id)
        report_path = Path(scan["report_path"])
        patched_ref = patched_image_ref(source_image_ref, patch_id)
        db.insert_patch_started(conn, patch_id, pipeline_id, scan_id, source_image_ref, patched_ref)
        copa_executable = tool_updates.copa_binary(conn)

    patch_tag = f"patched-{patch_id[:12]}"
    local_patched_ref = f"{source_repository(source_image_ref)}:{patch_tag}"

    command = [
        copa_executable,
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

    staged=None
    try:
        # Comprehensive mode intentionally omits the report argument entirely.
        copa_path = report_path.parent / f"copa-input-{patch_id}.json"
        policy_path = copa_path
        if strategy=="targeted":
            copa_path.write_bytes(remediation_audit.input_bytes(filtered_report))
            with db.connect() as conn:
                db.insert_artifact(conn, pipeline_id, scan_id, source_image_ref, "copa-input", "json", str(copa_path))
            command[command.index("-r") + 1] = str(copa_path)
        else:
            index=command.index("-r")
            del command[index:index+2]
            policy_path=report_path
        # Only use configured, signed same-release Debian mirrors. A local
        # preparation image is never pushed or presented as a security fix.
        from . import copa_mirrors
        if mirrors and (original_report.get("Metadata",{}).get("OS") or {}).get("Family")=="debian":
            staged=copa_mirrors.prepare(expected_id,original_report,mirrors)
            command[command.index("-i")+1]=staged["image_ref"]
            command[command.index("--addr")+1]="docker://"
            local_patched_ref=source_repository(staged["image_ref"])+":"+patch_tag
        job_watch.emit("copa_comprehensive" if strategy=="comprehensive" else "copa_targeted")
        # Capture Copa stderr so a failed patch has a concrete diagnostic in
        # the persisted patch/job error instead of only an exit status.
        copa_version, _ = tool_updates.command_version([copa_executable, "--version"])
        _, buildkit_info = tool_updates.command_version(["docker", "exec", env("BUILDKIT_CONTAINER", "appsec-buildkit"), "buildkitd", "--version"])
        from psycopg.types.json import Jsonb
        with db.connect() as conn:
            conn.execute("UPDATE patch_runs SET execution_evidence=%s WHERE id=%s",
                         (Jsonb({"copa_version": copa_version, "buildkit_version": buildkit_info,
                                 "source_image": source_image_ref,
                                 "strategy":strategy, "package_repository":staged,
                                 "remediation_input": remediation_audit.input_manifest(filtered_report) if filtered_report is not None else None}), patch_id))
        policy_context=(patch_sources.policy_environment(source_image_ref,policy_path,local_source=staged["image_ref"])
                        if staged else patch_sources.policy_environment(source_image_ref,policy_path))
        with policy_context as environment:
            if environment and environment.get("EXPERIMENTAL_BUILDKIT_SOURCE_POLICY"):
                source_rules = json.loads(Path(environment["EXPERIMENTAL_BUILDKIT_SOURCE_POLICY"]).read_text())["rules"]
                helper_refs = sorted({rule["updates"]["identifier"] for rule in source_rules if rule["action"] == "CONVERT"})
                with db.connect() as conn:
                    conn.execute("UPDATE patch_runs SET execution_evidence=COALESCE(execution_evidence,'{}'::jsonb) || %s WHERE id=%s",
                                 (Jsonb({"helper_sources": helper_refs}), patch_id))
            job_watch.emit("patch")
            run_command(command, capture_errors=True, environment=environment)
        patched_id = scan_evidence.local_image_id(local_patched_ref)
        if patched_id == expected_id or (staged and patched_id==staged["image_id"]):
            raise RuntimeError("SCAN_EVIDENCE_INVALID: Copa output is identical to its input; no verified patch")
        if staged:
            copa_mirrors.verify_candidate(expected_id,patched_id)
        with db.connect() as conn:
            db.update_patch_success(conn, patch_id, str(copa_path) if filtered_report is not None else None)
            conn.execute("UPDATE patch_runs SET local_image_id=%s WHERE id=%s", (patched_id, patch_id))
            conn.execute("""
                UPDATE patch_runs SET local_image_ref=%s, publication_status='prepared'
                WHERE id=%s
            """, (local_patched_ref, patch_id))
    except BaseException as exc:
        message = safe_message(exc, "patch_build")
        print("Patch build failed: " + message, flush=True)
        with db.connect() as conn:
            db.update_patch_failed(conn, patch_id, message)
        raise
    finally:
        if staged:
            copa_mirrors.cleanup(staged["image_ref"])

    print(json.dumps({"patch_id": patch_id, "patched_image": local_patched_ref,
                      "published": False}, indent=2))
    return patch_id, local_patched_ref


def create_diff(pipeline_id: str, original_scan_id: str, patched_scan_id: str) -> str:
    with db.connect() as conn:
        original_record = db.get_scan(conn, original_scan_id)
        patched_record = db.get_scan(conn, patched_scan_id)
        scan_evidence.validate_pair(original_record, patched_record)
        expected = conn.execute("SELECT local_image_id FROM patch_runs WHERE pipeline_id=%s AND local_image_ref=%s AND status='success' ORDER BY started_at DESC LIMIT 1",
                                (pipeline_id, patched_record["image_ref"])).fetchone()
        if not expected or expected["local_image_id"] != patched_record["raw_report"]["_appsec"]["image_id"]:
            raise RuntimeError("SCAN_EVIDENCE_INVALID: Rescan does not match the prepared patch")
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


def evaluate_policy(pipeline_id: str, scan_id: str, project_id: str | None = None, *, advisory: bool = False) -> str:
    with db.connect() as conn:
        scan = db.get_scan(conn, scan_id)
        rules_from_db = db.active_policy_rules(conn, project_id)
        status, rules, violations = (policy.recommend(scan, rules_from_db) if advisory
                                    else policy.evaluate(scan, rules_from_db))
        db.insert_policy_result(conn, pipeline_id, scan_id, status, rules, violations)

    print(json.dumps({"policy": status, "violations": violations}, indent=2))
    return status


def run_pipeline(image_ref: str, project_id: str | None = None, mode: str = "scan", job_id: str | None = None) -> str:
    """Scan an image and optionally prepare and evaluate a local patch."""
    if mode not in ("scan", "patch"):
        raise ValueError("mode must be scan or patch")
    with db.connect() as conn:
        image_id = db.get_or_create_image(conn, image_ref)
        pipeline_id = db.create_pipeline(conn, image_id, image_ref, project_id)
        if job_id:
            # Persist the link before network pulls, including failures.
            conn.execute("UPDATE pipeline_jobs SET pipeline_id=%s WHERE id=%s", (pipeline_id, job_id))

    try:
        print(f"SCAN_STAGE_START stage=image-pull pipeline={pipeline_id}", flush=True)
        with db.connect() as conn:
            resolved_image = image_sources.pull_image(conn, image_ref)
        print(f"SCAN_STAGE_DONE stage=image-pull pipeline={pipeline_id} source={resolved_image}", flush=True)
        original_scan_id = scan_image(resolved_image, "original", pipeline_id)
        generate_sbom(resolved_image, "original", original_scan_id, pipeline_id)
        policy_scan_id = original_scan_id
        if mode == "patch":
            try:
                _, patched_ref = patch_from_scan(original_scan_id)
            except scan_evidence.NoFixableOS:
                print("NO_FIXABLE_OS: Patch skipped; original findings retained.", flush=True)
                with db.connect() as conn:
                    db.insert_audit(conn, None, "patch.skipped.no_fixable_os", "pipeline", pipeline_id, {})
            else:
                patched_scan_id = scan_image(patched_ref, "patched", pipeline_id)
                generate_sbom(patched_ref, "patched", patched_scan_id, pipeline_id)
                create_diff(pipeline_id, original_scan_id, patched_scan_id)
                policy_scan_id = patched_scan_id
                evaluate_policy(pipeline_id, policy_scan_id, project_id, advisory=True)
        with db.connect() as conn:
            db.finish_pipeline(conn, pipeline_id, "success")
    except BaseException as exc:
        with db.connect() as conn:
            db.finish_pipeline(conn, pipeline_id, "failed", safe_message(exc, 'pipeline'))
        write_pipeline_report_if_ready(pipeline_id)
        raise

    write_pipeline_report_if_ready(pipeline_id)
    print_summary(pipeline_id)
    return pipeline_id


def continue_pipeline_patch(pipeline_id: str) -> str:
    """Continue a *previously reviewed* manual scan, never rescan unapproved.

    This path is only queued by a persisted operator approval. No automatic
    retries: patch/push is potentially non-idempotent.
    """
    with db.connect() as conn:
        pipeline = conn.execute(
            "SELECT id, project_id, status FROM pipeline_runs WHERE id = %s FOR UPDATE",
            (pipeline_id,),
        ).fetchone()
        if not pipeline or pipeline["status"] not in ("success", "policy_failed"):
            raise RuntimeError("manual patch requires a completed, reviewed scan")
        if conn.execute("SELECT 1 FROM patch_runs WHERE pipeline_id = %s LIMIT 1", (pipeline_id,)).fetchone():
            raise RuntimeError("this pipeline already has a patch attempt")
        original = conn.execute(
            """SELECT id FROM scan_runs
               WHERE pipeline_id = %s AND phase = 'original' AND status = 'success'
               ORDER BY started_at DESC LIMIT 1""",
            (pipeline_id,),
        ).fetchone()
        if not original:
            raise RuntimeError("original scan was not successful")
        source_scan_id = str(original["id"])
        automatic = bool(conn.execute("""SELECT 1 FROM manual_workflows w JOIN pipeline_jobs j ON j.id=w.patch_job_id
                WHERE j.pipeline_id=%s AND j.status='running' AND w.unattended
                AND w.execution_mode IN ('auto_patch','auto_optimize') AND w.decision='approve_patch'""",(pipeline_id,)).fetchone())
        project_id = str(pipeline["project_id"]) if pipeline["project_id"] else None
        conn.execute(
            "UPDATE pipeline_runs SET status = 'running', finished_at = NULL, error_message = NULL WHERE id = %s",
            (pipeline_id,),
        )
    try:
        _, patched_ref = patch_from_scan(source_scan_id,automatic=automatic)
        patched_scan_id = scan_image(patched_ref, "patched", pipeline_id)
        generate_sbom(patched_ref, "patched", patched_scan_id, pipeline_id)
        create_diff(pipeline_id, source_scan_id, patched_scan_id)
        evaluate_policy(pipeline_id, patched_scan_id, project_id, advisory=True)
        with db.connect() as conn:
            db.finish_pipeline(conn, pipeline_id, "success")
    except scan_evidence.NoFixableOS:
        # A continuation queued before the eligibility guard was introduced.
        # Preserve the previous approval in the audit trail, then close without a patch.
        with db.connect() as conn:
            rows = conn.execute("""
                UPDATE manual_workflows w SET decision='finish', updated_at=now()
                FROM pipeline_jobs j WHERE j.id=w.patch_job_id
                  AND j.pipeline_id=%s AND j.mode='continue_patch' AND j.status='running'
                  AND w.decision='approve_patch' AND w.publish_decision IS NULL
                RETURNING w.id
            """, (pipeline_id,)).fetchall()
            for row in rows:
                db.insert_audit(conn, None, "patch.skipped.no_fixable_os", "manual_workflow", str(row["id"]),
                                {"previous_decision": "approve_patch", "pipeline_id": pipeline_id})
            db.finish_pipeline(conn, pipeline_id, "success")
        print("NO_FIXABLE_OS: Patch skipped; original findings retained.", flush=True)
    except BaseException as exc:
        with db.connect() as conn:
            db.finish_pipeline(conn, pipeline_id, "failed", safe_message(exc, 'pipeline'))
        write_pipeline_report_if_ready(pipeline_id)
        raise
    write_pipeline_report_if_ready(pipeline_id)
    print_summary(pipeline_id)
    return pipeline_id


def publish_prepared_patch(pipeline_id: str, publish_job_id: str) -> str:
    """Human-approved single-attempt publication after successful patched policy."""
    with db.connect() as conn:
        row = conn.execute("""
            SELECT p.id, p.local_image_ref, p.patched_image_ref,
                   p.publication_status, p.local_image_id, pol.status AS policy_status,
                   pol.scanned_image_id
            FROM patch_runs p
            JOIN LATERAL (
                SELECT pol.status, sr.raw_report->'_appsec'->>'image_id' AS scanned_image_id FROM policy_results pol
                JOIN scan_runs sr ON sr.id=pol.scan_id
                WHERE pol.pipeline_id=p.pipeline_id AND sr.phase='patched' AND sr.status='success'
                  AND sr.image_ref=p.local_image_ref
                ORDER BY pol.created_at DESC LIMIT 1
            ) pol ON true
            WHERE p.pipeline_id=%s AND p.status='success'
              AND EXISTS (
                  SELECT 1 FROM manual_workflows w
                  JOIN pipeline_jobs scan_job ON scan_job.id=w.scan_job_id
                  WHERE scan_job.pipeline_id=p.pipeline_id AND w.publish_job_id=%s
                    AND w.publish_decision='approve_publish' AND w.published_by IS NOT NULL
              )
            ORDER BY p.started_at DESC LIMIT 1
            FOR UPDATE OF p
        """, (pipeline_id, publish_job_id)).fetchone()
        if not row or row["publication_status"] != "prepared" or not row["local_image_ref"]:
            raise RuntimeError("No prepared, unpublished image exists for this workflow")
        if row["policy_status"] not in ("recommended", "not_recommended", "passed"):
            raise RuntimeError("The post-patch recommendation is missing")
        # Revalidate registry authorization at execution time (revocation-safe).
        from .registry import image_registry
        host = image_registry(str(row["patched_image_ref"]))
        authorized = conn.execute("""
            SELECT 1 FROM registry_connections r
            JOIN manual_workflows w ON w.publish_job_id=%s
            WHERE r.host=%s AND r.allow_push=true
              AND (r.project_id IS NULL OR r.project_id=w.project_id)
            LIMIT 1
        """, (publish_job_id, host)).fetchone()
        if not authorized:
            raise RuntimeError("REGISTRY_PUSH_DENIED: destination permission revoked before execution")
        local_ref = str(row["local_image_ref"])
        if not row["local_image_id"] or row["local_image_id"] != row["scanned_image_id"] or scan_evidence.local_image_id(local_ref) != row["local_image_id"]:
            raise RuntimeError("SCAN_EVIDENCE_INVALID: Publication image does not match verified rescan")
        dest = str(row["patched_image_ref"])
        patch_id = str(row["id"])
        conn.execute("UPDATE patch_runs SET publication_status='publishing' WHERE id=%s", (patch_id,))
    try:
        run_command(["docker", "tag", str(row["local_image_id"]), dest], capture_errors=True)
        job_watch.emit("publish")
        push_command=["docker","push",dest]
        if job_watch.CURRENT.get() is not None:
            pushed=job_watch.observed_run(push_command)
            pushed.check_returncode()
        else:
            pushed=subprocess.run(push_command,check=True,capture_output=True,text=True)
        digest = scan_evidence.push_digest(pushed.stdout)
        if scan_evidence.local_image_id(dest) != row["local_image_id"]:
            raise RuntimeError("SCAN_EVIDENCE_INVALID: Destination tag changed during publication")
        remote_ref = source_repository(dest) + "@" + digest
        run_command(["docker", "pull", remote_ref], capture_errors=True)
        if scan_evidence.local_image_id(remote_ref) != row["local_image_id"]:
            raise RuntimeError("SCAN_EVIDENCE_INVALID: Published manifest does not match the verified rescan")
        with db.connect() as conn:
            conn.execute("""
                UPDATE patch_runs SET publication_status='published', published_at=now(), published_digest=%s,
                    execution_evidence=COALESCE(execution_evidence,'{}'::jsonb) || '{"remote_identity_verified":true}'::jsonb
                WHERE id=%s AND publication_status='publishing'
            """, (digest, patch_id))
    except BaseException:
        with db.connect() as conn:
            conn.execute("""
                UPDATE patch_runs SET publication_status='uncertain'
                WHERE id=%s AND publication_status='publishing'
            """, (patch_id,))
        raise
    # Publication is a completed registry side effect. Report refresh must not
    # turn a confirmed push into a retryable publication failure.
    try:
        write_pipeline_report_if_ready(pipeline_id)
    except Exception as exc:
        print("Publication report refresh failed: " + safe_detail(exc), file=sys.stderr, flush=True)
    return str(pipeline_id)


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
    if env("APPSEC_SUMMARY_COMPACT", "false").lower() == "true":
        print(json.dumps({"pipeline_id": pipeline_id, "status": (summary.get("pipeline") or {}).get("status"),
                          "scans": [{k: scan.get(k) for k in ("id", "phase", "status", "critical_count", "high_count", "medium_count", "low_count", "unknown_count")} for scan in summary.get("scans", [])],
                          "artifact_count": len(summary.get("artifacts", [])), "report_count": len(summary.get("reports", []))}, default=str), flush=True)
    else:
        print(json.dumps(summary, indent=2, default=str))


def ci_image(image_ref: str, mode: str = "scan") -> int:
    pipeline_id = run_pipeline(image_ref, mode=mode)
    with db.connect() as conn:
        summary = db.pipeline_summary(conn, pipeline_id)
    status = summary["pipeline"]["status"]
    # Execution success is not a security verdict. Keep manual policy advisory,
    # but enforce the explicit CI environment thresholds on verified evidence.
    scans = summary.get("scans", [])
    patched = [s for s in scans if s.get("phase") == "patched"]
    candidates = patched if patched else [s for s in scans if s.get("phase") == "original"]
    scan = candidates[-1] if candidates else None
    gate = "invalid_evidence"
    if status == "success" and scan and scan.get("status") == "success":
        evidence = (scan.get("raw_report") or {}).get("_appsec") or {}
        if evidence.get("verified") and evidence.get("image_id"):
            gate, rules, violations = policy.evaluate(scan, policy.rules_from_env())
            with db.connect() as conn:
                db.insert_policy_result(conn, pipeline_id, str(scan["id"]), gate, rules, violations)
                if gate != "passed":
                    db.finish_pipeline(conn, pipeline_id, "policy_failed", "CI severity thresholds exceeded")
            write_pipeline_report_if_ready(pipeline_id)
    print(json.dumps({"pipeline_id": pipeline_id, "execution_status": status, "ci_gate": gate}, indent=2))
    return 0 if status == "success" and gate == "passed" else 1


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
    run_parser.add_argument("--patch", action="store_true", help="Prepare and rescan a local patched image")

    enqueue_parser = subparsers.add_parser("enqueue")
    enqueue_parser.add_argument("image")
    enqueue_parser.add_argument("--priority", type=int, default=100)
    enqueue_parser.add_argument("--patch", action="store_true", help="Queue local patch preparation and rescanning")

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
    ci_image_parser.add_argument("--patch", action="store_true", help="Evaluate a locally patched image")
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

    audit_parser = subparsers.add_parser("remediation-audit", help="Read-only finding scope and rescan diagnostics")
    audit_parser.add_argument("--pipeline-id", required=True)

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
    if args.command == "remediation-audit":
        with db.connect() as conn:
            payload = db.pipeline_summary(conn, args.pipeline_id)
        if not payload or not payload.get("pipeline"):
            raise RuntimeError("Pipeline not found")
        result = remediation_audit.analyze(payload)
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0 if result["status"] == "original_verified" else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
