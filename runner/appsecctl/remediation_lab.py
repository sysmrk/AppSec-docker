"""Explicit, isolated v3 candidate generation. Never part of a publish workflow.

Run only on an isolated staging host. Uses exact source digest and mandatory
approved LLB source policy, no registry writes or database mutations.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from uuid import UUID, uuid4

from . import db, image_sources, patch_sources, scan_evidence, remediation_audit, tool_updates, library_remediation
from .errors import safe_detail

SUPPORTED_COPA = "0.15.0"
STRATEGIES = ("os_targeted", "os_comprehensive", *library_remediation.TYPES)
CONFIG_KEYS = ("Entrypoint", "Cmd", "User", "WorkingDir", "Env", "ExposedPorts",
               "Healthcheck", "Volumes", "StopSignal")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def docker_json(args, timeout=60):
    try:
        result = subprocess.run(["docker", *args], capture_output=True, text=True, check=True, timeout=timeout)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError("Docker inspection failed: " + safe_detail(exc.stderr)) from None


def repository(ref):
    canonical = image_sources.canonical_ref(ref).split("@", 1)[0]
    return canonical.rsplit(":", 1)[0] if ":" in canonical.rsplit("/", 1)[-1] else canonical


def validate_source(source, original_ref, sources):
    if not isinstance(source, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.:-]*(?:/[a-z0-9][a-z0-9._-]*)+@sha256:[a-f0-9]{64}", source):
        raise RuntimeError("Use an explicit single-platform repository@sha256 digest, without a tag")
    if image_sources.canonical_ref(source) != source or repository(source) != repository(original_ref):
        raise RuntimeError("Digest repository differs from the scanned, canonical source")
    if not sources or not any(source.startswith(image_sources.normalize_endpoint(s["host"])+"/") for s in sources):
        raise RuntimeError("Lab requires an enabled approved source; direct fallback is prohibited")
    return source


def verify_manifest(manifest, expected_id):
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2 or "manifests" in manifest:
        raise RuntimeError("Lab requires a single-platform schema 2 manifest, not a multi-platform index")
    if manifest.get("mediaType") not in ("application/vnd.oci.image.manifest.v1+json",
                                          "application/vnd.docker.distribution.manifest.v2+json"):
        raise RuntimeError("Unsupported image manifest type")
    if (manifest.get("config") or {}).get("digest") != expected_id:
        raise RuntimeError("Manifest config digest differs from the verified original image ID")


def inspect_local(ref):
    rows = docker_json(["image", "inspect", ref])
    if not isinstance(rows, list) or len(rows) != 1 or not DIGEST.fullmatch(rows[0].get("Id","")):
        raise RuntimeError("Cannot inspect unique local image identity")
    if rows[0].get("Os") != "linux" or rows[0].get("Architecture") != "amd64":
        raise RuntimeError("Initial lab supports linux/amd64 only")
    return rows[0]


def config_changes(before, after):
    a, b = before.get("Config"), after.get("Config")
    if not isinstance(a, dict) or not isinstance(b, dict):
        raise RuntimeError("Missing image configuration")
    return [key for key in CONFIG_KEYS if a.get(key) != b.get(key)]


def command_for(binary, source, tag, strategy, report_path, timeout, buildkit, level="patch"):
    if level not in ("patch", "minor"):
        raise ValueError("Invalid library version bump limit")
    if strategy not in STRATEGIES or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", buildkit):
        raise ValueError("Invalid lab strategy or executor name")
    if not re.fullmatch(r"v3-lab-[a-f0-9]{32}", tag):
        raise ValueError("Invalid unique lab tag")
    args = [binary, "patch", "-i", source, "-t", tag,
            "--addr", "docker-container://" + buildkit, "--platform", "linux/amd64",
            "--timeout", str(timeout) + "s", "--loader", "docker"]
    if strategy != "os_comprehensive":
        args.extend(["--report", str(report_path)])
    if strategy in library_remediation.TYPES:
        args.extend(["--pkg-types", "library", "--library-patch-level", level])
    # No report means comprehensive OS update. Never append user/AI CLI args.
    # No --push, --ignore-errors, --config or other experimental flags.
    return args


def run_candidate(scan_id, source, strategy, timeout, level="patch"):
    if os.getenv("APPSEC_ENABLE_REMEDIATION_LAB", "") != "true":
        raise RuntimeError("Lab disabled: use a dedicated isolated host and explicit APPSEC_ENABLE_REMEDIATION_LAB=true")
    if strategy not in STRATEGIES or not 60 <= timeout <= 7200 or level not in ("patch", "minor"):
        raise ValueError("Invalid strategy or timeout")
    if strategy in library_remediation.TYPES and os.getenv("APPSEC_ENABLE_LIBRARY_LAB") != "true":
        raise RuntimeError("Experimental library lab requires explicit APPSEC_ENABLE_LIBRARY_LAB=true; public package egress must be approved")
    with db.connect() as conn:
        scan = db.get_scan(conn, str(UUID(scan_id)))
        sources = image_sources.configured_sources(conn)
        binary = tool_updates.copa_binary(conn)
    if scan.get("phase") != "original" or not remediation_audit.verified(scan):
        raise RuntimeError("Lab requires a verified original scan")
    report = scan["raw_report"]
    expected_id = report["_appsec"]["image_id"]
    source = validate_source(source, scan["image_ref"], sources)
    # Do not silently fetch a different platform or moving tag. The exact
    # pinned source must already be available locally on the isolated daemon.
    original = inspect_local(source)
    if original["Id"] != expected_id:
        raise RuntimeError("Local digest reference does not match the saved scan")
    host = subprocess.run(["docker","info","--format","{{.OSType}}/{{.Architecture}}"],
                          capture_output=True,text=True,check=True,timeout=30).stdout.strip()
    if host not in ("linux/x86_64", "linux/amd64"):
        raise RuntimeError("Lab executor requires a native linux/amd64 daemon")
    manifest = docker_json(["manifest", "inspect", source])
    verify_manifest(manifest, expected_id)
    version, _ = tool_updates.command_version([binary, "--version"])
    if version != SUPPORTED_COPA:
        raise RuntimeError("Lab requires Copa " + SUPPORTED_COPA + "; validate other releases separately")
    buildkit = os.getenv("BUILDKIT_CONTAINER", "appsec-buildkit")
    buildkit_version, _ = tool_updates.command_version(["docker","exec",buildkit,"buildkitd","--version"])
    if not buildkit_version:
        raise RuntimeError("BuildKit version unavailable")
    tag = "v3-lab-" + uuid4().hex
    destination = repository(source) + ":" + tag
    with tempfile.TemporaryDirectory(prefix="appsec-v3-lab-") as tmp:
        policy_report = Path(tmp)/"source-metadata.json"
        policy_report.write_bytes(remediation_audit.input_bytes(report))
        input_path = Path(tmp)/"targeted-input.json"
        manifest_input, library_selection = None, None
        extra_groups = []
        if strategy == "os_targeted":
            filtered = scan_evidence.copa_report(report)
            input_path.write_bytes(remediation_audit.input_bytes(filtered))
            manifest_input = remediation_audit.input_manifest(filtered)
        elif strategy in library_remediation.TYPES:
            filtered, library_selection = library_remediation.prepare(scan,strategy,level,original.get("Config"))
            input_path.write_bytes(remediation_audit.input_bytes(filtered))
            manifest_input = remediation_audit.input_manifest(filtered)
            extra_groups = [[x] for x in library_selection["helper_refs"]]
        args = command_for(binary,source,tag,strategy,input_path,timeout,buildkit,level)
        with redirect_stdout(sys.stderr), patch_sources.policy_environment(source, policy_report, extra_groups=extra_groups) as env:
            if not env or not env.get("EXPERIMENTAL_BUILDKIT_SOURCE_POLICY"):
                raise RuntimeError("No approved BuildKit source policy; candidate generation refused")
            # A pinned, same-repository input and known OS helper mapping.
            # Source policy is not a network firewall; isolation is mandatory.
            policy_bytes = Path(env["EXPERIMENTAL_BUILDKIT_SOURCE_POLICY"]).read_bytes()
            policy_hash = hashlib.sha256(policy_bytes).hexdigest()
            env = {**env, "COPA_EXPERIMENTAL":"1" if strategy in library_remediation.TYPES else "0"}
            try:
                subprocess.run(args, check=True, env=env, capture_output=True,
                               text=True, timeout=timeout+60)
            except subprocess.CalledProcessError as exc:
                raise RuntimeError("Lab candidate build failed: "+safe_detail(exc.stderr)) from None
    candidate = inspect_local(destination)
    if candidate["Id"] == expected_id or inspect_local(source)["Id"] != expected_id:
        raise RuntimeError("Candidate identity is unchanged or original identity no longer matches")
    changes = config_changes(original,candidate)
    return {"schema":"appsec.remediation-lab/v1", "status":"config_changed" if changes else "candidate_prepared",
            "strategy":strategy, "source_scan_id":scan_id, "source":source, "source_image_id":expected_id,
            "candidate":destination, "candidate_image_id":candidate["Id"],
            "source_policy_sha256":policy_hash, "targeted_input":manifest_input,
            "library_selection":library_selection,
            "copa_version":version, "buildkit_version":buildkit_version,
            "changed_config_fields":changes, "verification_required":True,
            "functional_test_passed":False, "publication_authorized":False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-id",required=True)
    parser.add_argument("--source",required=True)
    parser.add_argument("--strategy",required=True,choices=STRATEGIES)
    parser.add_argument("--timeout",type=int,default=1800)
    parser.add_argument("--library-level",choices=("patch","minor"),default="patch")
    parser.add_argument("--confirm-isolated-lab",action="store_true",required=True)
    args = parser.parse_args(argv)
    try:
        result = run_candidate(args.scan_id,args.source,args.strategy,args.timeout,args.library_level)
    except (RuntimeError,ValueError,OSError,subprocess.SubprocessError) as exc:
        # Do not print raw subprocess stderr or credentials. A timed-out
        # BuildKit job may require manual reconciliation on the isolated host.
        print("LAB_FAILED: "+safe_detail(exc),file=sys.stderr)
        return 1
    print(json.dumps(result,indent=2,ensure_ascii=True))
    return 0 if result["status"] == "candidate_prepared" else 1


if __name__ == "__main__":
    raise SystemExit(main())
