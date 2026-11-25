"""Deterministic, non-executable remediation planning contract.

Scanner facts and proposed strategy identifiers are separate. A plan never
contains shell commands, inferred fix versions, credentials or executable input.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib

from . import remediation_audit as audit, scan_evidence

SCHEMA = "appsec.remediation-plan/v1"
STRATEGIES = {
    "os_targeted": ("Targeted OS update", "existing_workflow", "Resolve signed vendor packages and validate installed versions."),
    "os_comprehensive": ("Comprehensive OS update", "experimental", "Benchmark full same-release package update; validate dependency and runtime compatibility."),
    "python_in_image": ("Python in-image update", "experimental", "Verify pip environment, wheel provenance, dependency closure and native extensions."),
    "node_in_image": ("Node.js in-image update", "experimental", "Verify npm layout, lockfile, native addons and dependency closure."),
    "source_rebuild": ("Source dependency update and rebuild", "requires_source", "Use trusted source, build context and lockfile; rebuild and test."),
    "base_image_review": ("Base image replacement review", "review_only", "Establish trusted compatible base image and application rebuild path."),
    "advisory_review": ("Vendor advisory and package availability review", "review_only", "Check vendor advisories and signed repository metadata; do not invent a fix version."),
    "manual_review": ("Manual evidence review", "review_only", "Resolve uncertain package identity or unsupported ecosystem before execution."),
}
RANK = {"CRITICAL": 0, "HIGH": 1, "UNKNOWN": 2, "MEDIUM": 3, "LOW": 4}


def digest(value):
    return hashlib.sha256(audit.input_bytes(value)).hexdigest()


def package_options(cls, kind, known, uncertain):
    if uncertain:
        return ["manual_review"]
    if cls == "os-pkgs":
        return (["os_targeted", "os_comprehensive", "base_image_review"] if known
                else ["advisory_review", "os_comprehensive", "base_image_review"])
    if cls == "lang-pkgs":
        if not known:
            return ["advisory_review", "source_rebuild"]
        if kind in ("python-pkg", "pip", "pipenv", "poetry"):
            return ["source_rebuild", "python_in_image"]
        if kind in ("node-pkg", "npm", "yarn", "pnpm"):
            # Only npm is an upstream in-image experimental backend. Other
            # layouts require explicit investigation, not npm execution.
            return ["source_rebuild"] + (["node_in_image"] if kind in ("node-pkg", "npm") else [])
        return ["source_rebuild"]
    return ["manual_review"]


def build(payload, stage="original"):
    if stage not in ("original", "residual"):
        raise ValueError("Unknown remediation stage")
    scans = payload.get("scans") or []
    phase = "original" if stage == "original" else "patched"
    scan = next((s for s in reversed(scans) if s.get("phase") == phase), None)
    empty = {"schema": SCHEMA, "stage": stage, "status": "evidence_unavailable",
             "plan_digest": None, "actions": [], "strategy_summary": {},
             "finding_count": None, "package_group_count": None, "execution_authorized": False}
    if not audit.verified(scan):
        return empty
    if stage == "residual" and audit.analyze(payload)["comparison"] != "observed":
        return empty
    report = scan["raw_report"]
    evidence = report["_appsec"]
    findings, inventory, _ = audit.index(report)
    grouped = defaultdict(list)
    for key, entries in findings.items():
        grouped[key[:4]].extend(entries)
    actions = []
    for key, entries in grouped.items():
        cls, kind, target, pkg = key
        installed = sorted({v["InstalledVersion"] for v in entries})
        known = sum(scan_evidence.has_fix(v) for v in entries)
        # Keep multiple versions separate from actionable package resolution.
        # A scan alone cannot identify the correct installation instance.
        uncertain = len(installed) != 1 or not installed[0] or not inventory.get(key) or not set(installed) <= inventory[key]
        severity_counts = dict(Counter(
            s if s in RANK else "UNKNOWN" for s in (str(v.get("Severity") or "UNKNOWN").upper() for v in entries)))
        highest = min(severity_counts, key=lambda s: RANK[s])
        options = []
        for strategy in package_options(cls, kind, known, uncertain):
            label, readiness, requirement = STRATEGIES[strategy]
            options.append({"strategy": strategy, "label": label, "readiness": readiness,
                            "requirement": requirement})
        row = {"package": pkg, "class": cls, "type": kind, "target": target,
               "installed_versions": installed,
               "reported_fix_versions": sorted({v["FixedVersion"] for v in entries if scan_evidence.has_fix(v)}),
               "finding_ids": sorted({v["VulnerabilityID"] for v in entries}),
               "finding_count": len(entries), "known_fix_count": known,
               "no_reported_fix_count": len(entries)-known, "severity_counts": severity_counts,
               "highest_severity": highest, "identity_uncertain": uncertain,
               "options": options, "preferred_strategy": options[0]["strategy"]}
        row["action_id"] = digest([str(scan["id"]), list(key)])
        actions.append(row)
    actions.sort(key=lambda x: (RANK[x["highest_severity"]], -x["known_fix_count"],
                                x["package"], x["action_id"]))
    # Preferred strategy is a planning classification, not an execution choice.
    summary = defaultdict(lambda: {"package_groups": 0, "findings": 0, "reported_fix_findings": 0})
    for row in actions:
        entry = summary[row["preferred_strategy"]]
        entry["package_groups"] += 1
        entry["findings"] += row["finding_count"]
        entry["reported_fix_findings"] += row["known_fix_count"]
    plan = {**empty, "status": "planned", "scan_id": str(scan["id"]),
            "image_id": evidence["image_id"], "evidence_sha256": digest(report),
            "actions": actions, "strategy_summary": dict(summary),
            "finding_count": sum(r["finding_count"] for r in actions),
            "package_group_count": len(actions),
            "limitations": ["Reported fix versions are evidence, not a dependency solution.",
                            "No package repository or compatibility check has been performed.",
                            "Experimental strategies do not authorize execution.",
                            "All severities are included in planning."]}
    plan["plan_digest"] = digest(plan)
    return plan


def page(plan, offset=0, limit=25):
    if not 0 <= offset or not 1 <= limit <= 100:
        raise ValueError("Invalid plan page")
    total = len(plan["actions"])
    return {**plan, "actions": plan["actions"][offset:offset+limit], "offset": offset,
            "limit": limit, "next_offset": offset+limit if offset+limit < total else None}


def validate_selection(plan, plan_digest, selections):
    """Validate typed AI/human selections against freshly computed evidence.

    This is a dry-run contract check, never package validation or approval.
    """
    if plan["status"] != "planned" or plan["plan_digest"] != plan_digest:
        raise ValueError("Plan evidence is stale or unavailable")
    if not isinstance(selections, list) or not 1 <= len(selections) <= 100:
        raise ValueError("Select 1–100 actions")
    by_id = {row["action_id"]: row for row in plan["actions"]}
    seen = set()
    validated = []
    for selection in selections:
        if not isinstance(selection, dict) or set(selection) != {"action_id", "strategy"}:
            raise ValueError("Only action_id and strategy are accepted")
        aid, strategy = selection["action_id"], selection["strategy"]
        if not isinstance(aid, str) or not isinstance(strategy, str) or aid in seen or aid not in by_id:
            raise ValueError("Unknown or duplicate action")
        seen.add(aid)
        row = by_id[aid]
        option = next((o for o in row["options"] if o["strategy"] == strategy), None)
        if option is None:
            raise ValueError("Strategy is not allowed for this action")
        validated.append({"action_id": aid, "strategy": strategy, "readiness": option["readiness"],
                          "package": row["package"], "requirement": option["requirement"]})
    return {"schema": "appsec.remediation-selection/v1", "status": "selection_validated",
            "plan_digest": plan_digest, "selections": validated, "execution_authorized": False,
            "package_compatibility_verified": False}
