#!/usr/bin/env python3
"""Compare preloaded image candidates with frozen Trivy DB content.

No pulls, no patch execution, no registry writes, no Docker socket in scanner.
Docker save archives are temporary; raw reports and provenance stay on disk.
Run on a dedicated local Linux/WSL Docker host with adequate disk capacity.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from uuid import uuid4

from . import remediation_audit as audit, scan_evidence


def snapshot_manifest(root: Path) -> dict:
    files = {}
    for folder in ("db", "java-db"):
        path = root / folder
        if not path.exists():
            continue
        if path.is_symlink() or not path.is_dir():
            raise RuntimeError("Invalid DB snapshot directory")
        for entry in sorted(path.rglob("*")):
            if entry.is_symlink():
                raise RuntimeError("Symlinks are not permitted in DB snapshots")
            if entry.is_file():
                with entry.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else hash_stream(stream)
                files[entry.relative_to(root).as_posix()] = digest
            elif not entry.is_dir():
                raise RuntimeError("Unsupported DB snapshot entry")
    if not {"db/trivy.db", "db/metadata.json"} <= files.keys():
        raise RuntimeError("A prepared Trivy vulnerability database and metadata are required")
    return files


def hash_stream(stream):
    h = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        h.update(block)
    return h.hexdigest()


def write_json(path, data):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, ensure_ascii=True)


def run_checked(command, timeout):
    subprocess.run(command, check=True, timeout=timeout)


def scanner_args(scanner_id, work, name):
    return ["docker", "run", "--rm", "--name", name, "--pull=never", "--network", "none",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--mount", f"type=bind,src={work / 'cache'},dst=/root/.cache/trivy",
            "--mount", f"type=bind,src={work / 'image.tar'},dst=/image.tar,readonly",
            "--mount", f"type=bind,src={work / 'output'},dst=/output",
            scanner_id, "image", "--input", "/image.tar",
            "--scanners", "vuln", "--pkg-types", "os,library", "--list-all-pkgs",
            "--ignore-unfixed=false", "--ignorefile", "/dev/null",
            "--skip-db-update", "--skip-java-db-update", "--offline-scan",
            "--format", "json", "--output", "/output/report.json"]


def scan_one(ref, iid, scanner_id, frozen, manifest, output, label, timeout):
    with tempfile.TemporaryDirectory(prefix="appsec-v3-") as tmp:
        work = Path(tmp)
        cache = work / "cache"
        cache.mkdir()
        for folder in ("db", "java-db"):
            if (frozen / folder).is_dir():
                shutil.copytree(frozen / folder, cache / folder)
        if snapshot_manifest(cache) != manifest:
            raise RuntimeError("DB copy differs from frozen snapshot")
        (work / "output").mkdir()
        # Save the immutable local ID; a tag moving during the experiment cannot switch input.
        run_checked(["docker", "image", "save", "--output", str(work / "image.tar"), iid], timeout)
        name = "appsec-v3-bench-" + uuid4().hex
        try:
            run_checked(scanner_args(scanner_id, work, name), timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            try:
                subprocess.run(["docker", "rm", "-f", name], timeout=30, check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except (OSError, subprocess.SubprocessError):
                print("Inspect scanner cleanup: " + name, file=sys.stderr)
            raise
        if snapshot_manifest(cache) != manifest:
            raise RuntimeError("Scanner database content changed during benchmark")
        report = json.loads((work / "output" / "report.json").read_text(encoding="utf-8"))
        scan_evidence.validate_report(report, iid)
        report["_appsec"] = {"verified": True, "scope": audit.SCOPE, "image_id": iid,
                             "scanner_image": scanner_id}
        scan = {"id": label, "phase": "original" if label == "original" else "patched",
                "status": "success", "image_ref": ref, "raw_report": report}
        if not audit.verified(scan):
            raise RuntimeError("Benchmark scan lacks required inventory/evidence")
        write_json(output / (label + ".json"), report)
        return scan


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner", required=True, help="Already available Trivy image reference or ID")
    parser.add_argument("--db-cache", required=True, type=Path, help="Prepared DB cache; quiesce updater before copying")
    parser.add_argument("--original", required=True, help="Already available original image")
    parser.add_argument("--candidate", action="append", required=True, help="Already available candidate; repeat to compare")
    parser.add_argument("--output", required=True, type=Path, help="New output directory")
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 86400 or len(args.candidate) > 12:
        parser.error("Timeout must be 1–86400 seconds; at most 12 candidates")
    os.umask(0o077)
    scanner_id = scan_evidence.local_image_id(args.scanner)
    refs = [args.original, *args.candidate]
    ids = [scan_evidence.local_image_id(ref) for ref in refs]
    if len(set(ids)) != len(ids):
        parser.error("Original and candidates must be distinct immutable image IDs")
    cache = args.db_cache.resolve(strict=True)
    manifest = snapshot_manifest(cache)
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="appsec-v3-snapshot-") as tmp:
        frozen = Path(tmp)
        for folder in ("db", "java-db"):
            if (cache / folder).is_dir():
                shutil.copytree(cache / folder, frozen / folder)
        if snapshot_manifest(frozen) != manifest or snapshot_manifest(cache) != manifest:
            raise RuntimeError("Source DB changed while freezing; stop refresh and repeat")
        write_json(output / "manifest.json", {"schema": "appsec.benchmark/v1", "scanner_image_id": scanner_id,
                   "database_files_sha256": manifest, "images": [{"ref": r, "id": i} for r,i in zip(refs,ids)],
                   "scan_mode": "offline archive, OS and library; no DB updates; no application execution"})
        original = scan_one(refs[0], ids[0], scanner_id, frozen, manifest, output, "original", args.timeout)
        comparisons = []
        for idx, (ref, iid) in enumerate(zip(refs[1:], ids[1:]), 1):
            label = f"candidate-{idx}"
            candidate = scan_one(ref, iid, scanner_id, frozen, manifest, output, label, args.timeout)
            result = audit.analyze({"scans": [original, candidate]}, benchmark=True)
            if result["comparison"] != "benchmark_observed":
                raise RuntimeError("Benchmark comparison evidence unavailable")
            result["frozen_db_content_verified"] = True
            result["warnings"].append("Frozen DB files matched before and after each offline scan; offline coverage and candidate provenance remain limited.")
            result["scanner_image_id"] = scanner_id
            write_json(output / (label + "-comparison.json"), result)
            comparisons.append({"candidate": ref, "comparison_file": label + "-comparison.json",
                                "cohorts": result["cohorts"], "introduced": result["introduced"]})
        write_json(output / "summary.json", comparisons)
    print(str(output / "summary.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
