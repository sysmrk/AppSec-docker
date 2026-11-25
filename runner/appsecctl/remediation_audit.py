"""Read-only remediation diagnostics: measure scope, not speculative root causes.

No network, subprocess, mutation or LLM calls. Counts are finding occurrences
(all severities), not unique CVEs. Unknown coverage is never treated as a fix.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import re

from . import scan_evidence

SCHEMA = "appsec.remediation-audit/v1"
SCOPE = "os,library; all fix statuses"
COHORTS = ("os_known_fix", "os_no_reported_fix", "application_known_fix",
           "application_no_reported_fix", "other", "ambiguous")


def input_bytes(report: dict) -> bytes:
    """Canonical UTF-8 bytes actually passed to the v2 patch backend."""
    return json.dumps(report, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def input_manifest(report: dict) -> dict:
    return {"sha256": hashlib.sha256(input_bytes(report)).hexdigest(),
            "finding_count": sum(len(t.get("Vulnerabilities") or [])
                                 for t in report["Results"])}


def verified(scan):
    if not isinstance(scan, dict) or scan.get("status") != "success":
        return False
    try:
        report = scan["raw_report"]
        evidence = report["_appsec"]
        image_id = evidence["image_id"]
        if (evidence.get("verified") is not True or evidence.get("scope") != SCOPE
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)):
            return False
        scan_evidence.validate_report(report, image_id)
        for target in report["Results"]:
            if not isinstance(target.get("Type"), str):
                return False
            if any(not isinstance(v.get(k), str) for v in (target.get("Vulnerabilities") or [])
                   for k in ("PkgName", "VulnerabilityID", "InstalledVersion")):
                return False
            if not isinstance(target.get("Packages", []), list):
                return False
        return True
    except (KeyError, TypeError, AttributeError, ValueError, RuntimeError):
        return False


def target_key(target):
    cls, kind, name = target["Class"], target["Type"], target["Target"]
    return (cls, kind, scan_evidence.stable_target(name) if cls == "os-pkgs" else name)


def cohort(cls, finding):
    known = scan_evidence.has_fix(finding)
    if cls == "os-pkgs":
        return "os_known_fix" if known else "os_no_reported_fix"
    if cls == "lang-pkgs":
        return "application_known_fix" if known else "application_no_reported_fix"
    return "other"


def index(report):
    findings, inventory = defaultdict(list), defaultdict(set)
    covered = set()
    for target in report["Results"]:
        tk = target_key(target)
        packages = target.get("Packages") or []
        if packages:
            covered.add(tk)
        for pkg in packages:
            if isinstance(pkg, dict) and isinstance(pkg.get("Name"), str) and isinstance(pkg.get("Version"), str):
                inventory[tk + (pkg["Name"],)].add(pkg["Version"])
        for v in target.get("Vulnerabilities") or []:
            findings[tk + (v["PkgName"], v["VulnerabilityID"])].append(v)
    return findings, inventory, covered


def analyze(payload: dict) -> dict:
    """Summarize only evidence linked to this pipeline, including historical scans."""
    result = {"schema": SCHEMA, "status": "original_unverified",
              "comparison": "unavailable", "input_status": "not_recorded",
              "cohorts": {}, "groups": [], "introduced": None,
              "warnings": ["Counts include LOW; absence is not proof of remediation."]}
    scans = payload.get("scans") or []
    original = next((s for s in reversed(scans) if s.get("phase") == "original"), None)
    patched = next((s for s in reversed(scans) if s.get("phase") == "patched"), None)
    if not verified(original):
        return result
    result["status"] = "original_verified"
    a = original["raw_report"]
    before, old_inventory, _ = index(a)
    result["original_scan_id"] = str(original["id"])
    result["original_image_id"] = a["_appsec"]["image_id"]
    result["original_findings"] = sum(len(v) for v in before.values())
    expected = None
    try:
        expected = input_manifest(scan_evidence.copa_report(a))
    except scan_evidence.NoFixableOS:
        pass
    result["expected_v2_input"] = expected
    patches = payload.get("patches") or []
    patch = next((p for p in reversed(patches) if p.get("status") == "success"
                  and patched and p.get("local_image_ref") == patched.get("image_ref")
                  and p.get("local_image_id") == (patched.get("raw_report") or {}).get("_appsec", {}).get("image_id")), None)
    attempt = patch or (patches[-1] if patches else {})
    recorded = (attempt.get("execution_evidence") or {}).get("remediation_input")
    if recorded is not None:
        result["input_status"] = "matches_expected" if expected is not None and recorded == expected else "mismatch"
    elif expected is None:
        result["input_status"] = "no_os_candidates"
    result["recorded_input"] = recorded
    linked = bool(patch and any(str(d.get("original_scan_id")) == str(original["id"])
                  and patched and str(d.get("patched_scan_id")) == str(patched["id"])
                  for d in payload.get("diffs") or []))
    pair = bool(linked and verified(patched)
                and a["_appsec"]["image_id"] != patched["raw_report"]["_appsec"]["image_id"])
    after, new_inventory, coverage = {}, {}, set()
    if pair:
        b = patched["raw_report"]
        after, new_inventory, coverage = index(b)
        result["comparison"] = "observed"
        result["patched_scan_id"] = str(patched["id"])
        result["patched_image_id"] = b["_appsec"]["image_id"]
        result["patched_findings"] = sum(len(v) for v in after.values())
        result["introduced"] = sum(max(0, len(v) - len(before.get(k, []))) for k, v in after.items())
        ae, be = a["_appsec"], b["_appsec"]
        same = all(ae.get(k) and ae.get(k) == be.get(k) for k in ("trivy_version", "trivy_info", "scanner_image"))
        result["scanner_metadata_match"] = bool(same)
        result["warnings"].append("Scanner/DB metadata matches, but immutable DB content was not verified."
                                  if same else "Scanner/DB metadata differs or is missing; feed drift may explain differences.")
    else:
        result["warnings"].append("No linked, independently verified patched rescan; no disappearance rate.")
    stats = {k: {"original": 0, "remaining": 0 if pair else None,
                 "no_longer_detected": 0 if pair else None,
                 "coverage_unknown": 0 if pair else None} for k in COHORTS}
    for key, entries in sorted(before.items()):
        tk, pk = key[:3], key[:4]
        classes = {cohort(key[0], v) for v in entries}
        group = next(iter(classes)) if len(classes) == 1 else "ambiguous"
        if group == "ambiguous":
            result["warnings"].append("Mixed fix eligibility in one identity group; excluded from OS-specific attribution.")
        row = {"class": key[0], "type": key[1], "target": key[2], "package": key[3],
               "id": key[4], "cohort": group, "original": len(entries),
               "severities": sorted({str(v.get("Severity") or "UNKNOWN") for v in entries}),
               "reported_fixed_versions": sorted({v["FixedVersion"] for v in entries if scan_evidence.has_fix(v)}),
               "installed_before": sorted({v["InstalledVersion"] for v in entries}),
               "installed_after": None, "remaining": None, "no_longer_detected": None,
               "coverage_unknown": None, "observation": "not_rescanned"}
        stats[group]["original"] += len(entries)
        if pair:
            matches = after.get(key, [])
            versions = new_inventory.get(pk, set())
            row["installed_after"] = sorted(versions | {v["InstalledVersion"] for v in matches})
            remaining = min(len(entries), len(matches))
            absent = len(entries) - remaining
            # A missing target inventory is not evidence that the CVE disappeared.
            unknown = absent if tk not in coverage else 0
            row.update(remaining=remaining, no_longer_detected=absent-unknown, coverage_unknown=unknown)
            for field in ("remaining", "no_longer_detected", "coverage_unknown"):
                stats[group][field] += row[field]
            if unknown:
                row["observation"] = "target_inventory_missing"
            elif remaining:
                row["observation"] = ("still_detected_same_versions" if set(row["installed_before"]) == set(row["installed_after"])
                                      else "still_detected_version_changed")
            elif versions:
                row["observation"] = "no_longer_detected_package_present"
            else:
                row["observation"] = "no_longer_detected_package_not_in_inventory"
        result["groups"].append(row)
    for item in stats.values():
        item["disappearance_rate_pct"] = (round(100 * item["no_longer_detected"] / item["original"], 2)
                                           if pair and item["original"] and not item["coverage_unknown"] else None)
    result["cohorts"] = stats
    result["warnings"] = list(dict.fromkeys(result["warnings"]))
    return result
