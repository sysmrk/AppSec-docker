"""Evidence validation for full Trivy scans and Copa-specific inputs."""
from __future__ import annotations

import copy
import re
import subprocess


def local_image_id(reference: str) -> str:
    result = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", reference],
                            check=True, capture_output=True, text=True, timeout=30)
    identifier = result.stdout.strip()
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", identifier):
        raise RuntimeError("SCAN_EVIDENCE_INVALID: Docker did not return a valid image ID")
    return identifier


def validate_report(report: dict, expected_id: str) -> None:
    if not isinstance(report, dict) or report.get("ArtifactType") != "container_image":
        raise RuntimeError("SCAN_EVIDENCE_INVALID: Report is not a container image scan")
    metadata = report.get("Metadata") or {}
    if metadata.get("ImageID") != expected_id:
        raise RuntimeError("SCAN_EVIDENCE_INVALID: Trivy ImageID differs from Docker image ID")
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        raise RuntimeError("SCAN_EVIDENCE_INVALID: Trivy returned no scan targets; zero CVEs cannot be verified")
    if not any(r.get("Class") == "os-pkgs" and isinstance(r.get("Packages"), list) and r["Packages"]
               for r in results if isinstance(r, dict)):
        raise RuntimeError("SCAN_EVIDENCE_INVALID: OS package inventory missing or empty; zero CVEs cannot be verified")
    for result in results:
        if not isinstance(result, dict) or not result.get("Target") or not result.get("Class"):
            raise RuntimeError("SCAN_EVIDENCE_INVALID: Malformed scan target")
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list) or any(
            not isinstance(v, dict) or not v.get("VulnerabilityID") or not v.get("PkgName")
            for v in vulnerabilities
        ):
            raise RuntimeError("SCAN_EVIDENCE_INVALID: Malformed vulnerability results")


def stable_target(target: str) -> str:
    # Trivy OS target is normally "registry/image:tag (debian 13.x)".
    # Compare by distro family, not tag or OS minor version. Application
    # dependency paths remain distinct.
    match = re.search(r"\s+\(([A-Za-z][A-Za-z0-9_-]*)\s+[^()]+\)$", target)
    return "os:" + match.group(1).lower() if match else target


def copa_report(report: dict) -> dict:
    output = copy.deepcopy(report)
    output.pop("_appsec", None)
    output["Results"] = []
    for target in report.get("Results", []):
        if target.get("Class") == "os-pkgs":
            item = copy.deepcopy(target)
            item["Vulnerabilities"] = [v for v in item.get("Vulnerabilities") or [] if v.get("FixedVersion")]
            output["Results"].append(item)
    if not any(t["Vulnerabilities"] for t in output["Results"]):
        raise RuntimeError("SCAN_EVIDENCE_INVALID: No fixable OS vulnerabilities for Copa; finish without patching")
    return output


def validate_pair(original: dict, patched: dict) -> None:
    a = (original.get("raw_report") or {}).get("_appsec") or {}
    b = (patched.get("raw_report") or {}).get("_appsec") or {}
    if (original.get("status") != "success" or patched.get("status") != "success"
            or not a.get("verified") or not b.get("verified")
            or not a.get("image_id") or not b.get("image_id")
            or a["image_id"] == b["image_id"] or a.get("scope") != b.get("scope")):
        raise RuntimeError("SCAN_EVIDENCE_INVALID: Before/after scans are not independently verified and comparable")


def push_digest(output: str) -> str:
    matches = re.findall(r"\bdigest:\s*(sha256:[a-f0-9]{64})\b", output)
    if not matches:
        raise RuntimeError("SCAN_EVIDENCE_INVALID: Push returned no registry manifest digest; publication requires review")
    return matches[-1]
