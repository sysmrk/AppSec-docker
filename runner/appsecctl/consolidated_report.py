"""A single, self-contained, accessible Before/After pipeline report.

The report is regenerated at the same URL after patch/rescan. All counts come
from persisted Trivy scan rows and scan_diff records, never synthetic data.
"""
from __future__ import annotations

from html import escape
from typing import Any
from collections import defaultdict, deque, Counter
from .scan_evidence import stable_target


SEVERITIES = (("CRITICAL", "critical_count", "#d94362"),
              ("HIGH", "high_count", "#ef923c"),
              ("MEDIUM", "medium_count", "#e5bd56"),
               ("UNKNOWN", "unknown_count", "#8894a8"))


def e(value: Any) -> str:
    return escape(str(value) if value is not None else "—", quote=True)


def number(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (ValueError, TypeError):
        return 0


def phase(scans: list[dict], name: str) -> dict[str, Any] | None:
    matches = [s for s in scans if s.get("phase") == name]
    return matches[-1] if matches else None


def findings(scan: dict | None) -> list[dict]:
    if not scan:
        return []
    raw = scan.get("raw_report") or {}
    if not isinstance(raw, dict):
        return []
    result = []
    for target in raw.get("Results", []) or []:
        for v in target.get("Vulnerabilities", []) or []:
            result.append({
                "cve": v.get("VulnerabilityID"),
                "severity": (v.get("Severity") or "UNKNOWN").upper(),
                "class": target.get("Class") or "",
                "type": target.get("Type") or "",
                "severity_source": v.get("SeveritySource"),
                "vendor_severity": v.get("VendorSeverity") or {},
                "cvss": v.get("CVSS") or {},
                "status": v.get("Status"),
                "url": v.get("PrimaryURL"),
                "package": v.get("PkgName"),
                "installed": v.get("InstalledVersion"),
                "fixed": v.get("FixedVersion"),
                "target": target.get("Target"),
            })
    return result


def badge(value: str, kind: str) -> str:
    return '<span class="badge ' + kind + '">' + e(value) + "</span>"


def bars(scans: list[dict], original: dict | None, patched: dict | None) -> str:
    if not original or original.get("status") != "success":
        return '<p class="muted">Original scan is missing or did not complete successfully; counts are unavailable.</p>'
    if patched and patched.get("status") != "success":
        patched = None
    scale = max([number(s.get(field)) for s in scans if s.get("status") == "success" for _, field, _ in SEVERITIES] + [1])
    body = []
    for label, field, color in SEVERITIES:
        old = number(original.get(field))
        new = number(patched.get(field)) if patched else None
        old_width = max(1, round(old / scale * 100)) if old else 0
        new_width = max(1, round(new / scale * 100)) if new else 0
        body.append(
            '<div class="severity-row"><div class="severity-label" style="color:' + color + '">' + label + '</div>'
            '<div class="bar-pair"><div class="bar-lane"><div class="bar before" style="width:' +
            str(old_width) + '%;background:' + color + '"></div></div>'
            '<div class="bar-lane"><div class="bar after" style="width:' +
            str(new_width) + '%;background:' + color + '"></div></div></div>'
            '<div class="bar-count">' + str(old) + ' <span>→</span> ' + (str(new) if new is not None else "—") + "</div></div>"
        )
    return '<div class="legend"><span class="legend-before">■ Initial</span><span class="legend-after">■ After patch</span></div>' + "".join(body)


def finding_key(v: dict) -> tuple:
    return (v["cve"], v["package"], v["class"], v["type"],
            stable_target(str(v["target"] or "")))


def compare_findings(original, patched, verified):
    before = [v for v in findings(original) if v["severity"] != "LOW"]
    after = [v for v in findings(patched) if v["severity"] != "LOW"] if verified else []
    # Match using all severities, so a severity change to LOW is not a fix.
    pending = defaultdict(deque)
    for v in findings(patched) if verified else []:
        pending[finding_key(v)].append(v)
    rows = []
    for v in findings(original):
        bucket = pending[finding_key(v)]
        new = bucket.popleft() if verified and bucket else None
        if v["severity"] == "LOW" and (not new or new["severity"] == "LOW"):
            continue
        rows.append((v, new, "Remaining" if new else "Fixed" if verified else "Not rescanned"))
    if verified:
        rows.extend((None, v, "Introduced") for bucket in pending.values() for v in bucket if v["severity"] != "LOW")
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "UNKNOWN": 3, "LOW": 4}
    return sorted(rows, key=lambda row: (order.get((row[1] or row[0])["severity"], 3),
                                        str((row[1] or row[0])["cve"]), str((row[1] or row[0])["package"])))


def unknown_detail(v):
    if v["severity"] != "UNKNOWN":
        return ""
    # Retain vendor rating as evidence, not an invented authoritative rating.
    vendor = v["vendor_severity"]
    mapping = {0: "UNKNOWN", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
    ratings = ", ".join(str(k) + ": " + str(mapping.get(x, x)) for k, x in vendor.items()) if isinstance(vendor, dict) else ""
    scores = []
    if isinstance(v["cvss"], dict):
        for name, data in v["cvss"].items():
            if isinstance(data, dict):
                scores.extend(str(name) + " " + key + "=" + str(data[key]) for key in ("V3Score", "V2Score", "V40Score") if key in data)
    return "Trivy severity unavailable; manual triage. " + ("Vendor: " + ratings + ". " if ratings else "") + ("CVSS: " + ", ".join(scores) if scores else "No CVSS in scan evidence.")


def comparison_table(rows, verified):
    if not rows:
        return '<p class="muted">No recorded in-scope findings, or no verified results.</p>'
    body = []
    for old, new, state in rows:
        v = new or old
        sev = (old["severity"] + " → " + new["severity"]) if old and new and old["severity"] != new["severity"] else v["severity"]
        details = unknown_detail(v) or (unknown_detail(old) if old else "")
        body.append("<tr>" + "".join("<td>" + e(x) + "</td>" for x in (
            v["cve"], sev, v["package"], old["installed"] if old else None,
            new["installed"] if new else None, v["fixed"] or "No known fix", v["target"]))
            + '<td><span class="finding-state ' + ("fixed" if state == "Fixed" else "pending-state") + '">' + e(state)
            + '</span></td><td>' + e(details or v["status"] or "—") + "</td></tr>")
    return ('<p class="muted">Fixed = no longer detected in a verified comparable rescan; not proof of remediation. '
            'LOW-only findings are excluded from this report view; raw evidence and policy counts are retained.</p>'
            '<div class="table-scroll"><table><thead><tr><th>CVE / ID</th><th>Severity</th><th>Package</th>'
            '<th>Before</th><th>After</th><th>Vendor fix version</th><th>Target</th><th>Status</th><th>Triage</th>'
            '</tr></thead><tbody>' + "".join(body) + "</tbody></table></div>")


def package_upgrades(original, patched, verified):
    if not verified:
        return '<p class="muted">Package comparison requires verified scans.</p>'
    def inventory(scan):
        data = defaultdict(set)
        for target in (scan.get("raw_report") or {}).get("Results", []):
            for pkg in target.get("Packages") or []:
                if pkg.get("Name") and pkg.get("Version"):
                    data[(target.get("Class"), target.get("Type"), stable_target(str(target.get("Target") or "")), pkg["Name"])].add(str(pkg["Version"]))
        return data
    before, after = inventory(original), inventory(patched)
    if not before or not after:
        return '<p class="muted">Full package inventories not available in this historical scan.</p>'
    rows = []
    for key in sorted(before.keys() & after.keys(), key=str):
        if before[key] != after[key]:
            rows.append("<tr>" + "".join("<td>" + e(x) + "</td>" for x in (key[-1], ", ".join(sorted(before[key])), ", ".join(sorted(after[key])), key[2])) + "</tr>")
    return '<p class="muted">Version changes from actual Trivy package inventories; added/removed inventory keys: ' + str(len(after.keys()-before.keys())) + '/' + str(len(before.keys()-after.keys())) + '.</p><table><thead><tr><th>Package</th><th>Before</th><th>After</th><th>Target</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table>"



def render(resource_id: str, payload: dict[str, Any]) -> str:
    p = dict(payload.get("pipeline") or {})
    scans = [dict(x) for x in (payload.get("scans") or [])]
    original, patched = phase(scans, "original"), phase(scans, "patched")
    diff = (payload.get("diffs") or [])
    latest_diff = dict(diff[-1]) if diff else None
    policies = (payload.get("policies") or [])
    final_policy = next((dict(x) for x in reversed(policies)
                         if patched and str(x.get("scan_id")) == str(patched.get("id"))), None)
    if not patched or patched.get("status") != "success":
        final_policy = None
    a = (original.get("raw_report") or {}).get("_appsec") or {} if original else {}
    b = (patched.get("raw_report") or {}).get("_appsec") or {} if patched else {}
    verified_pair = bool(original and patched and original.get("status") == "success" and
                         patched.get("status") == "success" and a.get("verified") and b.get("verified") and
                         a.get("image_id") and b.get("image_id") and a["image_id"] != b["image_id"] and
                         a.get("scope") == b.get("scope"))
    if not verified_pair:
        final_policy = None
        latest_diff = None
    elif latest_diff and (str(latest_diff.get("original_scan_id")) != str(original.get("id")) or
                          str(latest_diff.get("patched_scan_id")) != str(patched.get("id"))):
        latest_diff = None
    recommended = str(final_policy.get("status")) if final_policy else "pending"
    advisory = {
        "recommended": ("Recommended for publication", "good", "Post-patch findings meet the configured recommendation thresholds."),
        "not_recommended": ("Publication not recommended", "bad", "Post-patch findings exceed advisory thresholds. A human must review the risks."),
        "pending": ("Recommendation pending", "neutral", "Recommendation is calculated only after the patched scan completes."),
    }.get(recommended, ("Legacy policy status: " + recommended, "neutral", "Older workflow policy result; please review before publishing."))
    original_total = sum(number(original.get(field)) for _,field,_ in SEVERITIES) if original and original.get("status") == "success" else None
    patched_total = sum(number(patched.get(field)) for _,field,_ in SEVERITIES) if patched and patched.get("status") == "success" else None
    value = lambda x: str(x) if x is not None else "—"
    metric = lambda label,count,note: '<div class="metric"><span>' + e(label) + '</span><strong>' + e(value(count)) + '</strong><small>' + e(note) + "</small></div>"
    rows = compare_findings(original, patched, verified_pair)
    states = Counter(row[2] for row in rows)
    initial_rows = [old for old, new, state in rows if old and old["severity"] != "LOW"]
    final_rows = [v for v in findings(patched) if v["severity"] != "LOW"] if verified_pair else []
    initial_fixable = sum(bool(v["fixed"]) for v in initial_rows)
    removed_fixable = sum(bool(old["fixed"]) for old, new, state in rows if old and old["severity"] != "LOW" and state == "Fixed")
    cards = (metric("Initial scan", original_total, "CRITICAL, HIGH, MEDIUM and UNKNOWN; LOW excluded")
             + metric("After patch", patched_total, "Only real completed rescans")
             + metric("No longer detected", states["Fixed"] if verified_pair else None, "In-scope findings, not proof of remediation")
             + metric("Introduced", states["Introduced"] if verified_pair else None, "Newly detected in report scope"))
    changes = ""
    if latest_diff:
        changes = ('<div class="changes">' +
                   metric("Remaining", patched_total, "In-scope post-patch findings") +
                   metric("Net reduction", (original_total - patched_total) if original_total is not None and patched_total is not None else None,
                          "Initial minus final, LOW excluded") + "</div>")
    elif not patched:
        changes = '<p class="muted">No patched scan yet. Comparison will appear here after you approve local patch preparation and the rescan finishes.</p>'
    violations = list(final_policy.get("violations") or []) if final_policy else []
    reasons = "".join("<li>" + e(v.get("severity")) + ": " + e(v.get("count")) +
                      " found; recommended maximum " + e(v.get("limit")) + "</li>" for v in violations)
    recommendation = ('<div class="recommend ' + advisory[1] + '"><strong>' + e(advisory[0]) +
                      '</strong><p>' + e(advisory[2]) + "</p>" +
                      ("<ul>" + reasons + "</ul>" if reasons else "") + "</div>")
    errors = []
    for label, row in (("Pipeline", p), ("Original scan", original), ("Patched scan", patched)):
        if row and row.get("error_message"):
            errors.append('<div class="issue"><strong>' + e(label) + "</strong><p>" +
                          e(row["error_message"]) + "</p></div>")
    for patch in payload.get("patches") or []:
        if patch.get("error_message"):
            errors.append('<div class="issue"><strong>Patch preparation</strong><p>' +
                          e(patch["error_message"]) + "</p></div>")
    banner = ('<div class="report-top"><div><div class="kicker">APPSEC · CONSOLIDATED IMAGE REPORT</div>'
              "<h1>" + e(p.get("requested_image")) + "</h1><p>Pipeline " + e(resource_id) +
              " · " + e(p.get("started_at")) + "</p></div>" +
              badge("Execution: " + (p.get("status") or "queued"), "neutral") + "</div>")
    patch = (payload.get("patches") or [{}])[-1]
    publication = '<section><h2>Image identity and publication</h2>'
    for label, scan in (("Original scan", original), ("Patched rescan", patched)):
        evidence = (scan.get("raw_report") or {}).get("_appsec") or {} if scan else {}
        publication += '<p><strong>' + e(label) + '</strong>: ' + e(scan.get("image_ref") if scan else None) + '<br>Scan ID: ' + e(scan.get("id") if scan else None) + '<br>Image ID: ' + e(evidence.get("image_id")) + '<br>Registry references: ' + e(", ".join((scan.get("raw_report") or {}).get("Metadata", {}).get("RepoDigests") or []) if scan else None) + '<br>OS packages inspected: ' + e(evidence.get("os_package_count")) + '<br>Application packages inspected: ' + e(evidence.get("application_package_count")) + '<br>Finished: ' + e(scan.get("finished_at") if scan else None) + '</p>'
    approval = payload.get("approval") or {}
    publication += '<p>Patch approval: ' + e(approval.get("patch_approver")) + ' · ' + e(approval.get("approved_at")) + '<br>Publish approval: ' + e(approval.get("publish_approver")) + ' · ' + e(approval.get("publish_approved_at")) + '<br>Risk acceptance reason: ' + e(approval.get("risk_reason") or "Not recorded") + '</p>'
    publication += '<p>Patch execution: ' + e(patch.get("status")) + ' · ' + e(patch.get("started_at")) + ' → ' + e(patch.get("finished_at")) + '<br>Rescan: ' + e(patched.get("status") if patched else None) + '<br>Security recommendation: ' + e(recommended) + '</p>'
    publication += '<p>Local patched image: ' + e(patch.get("local_image_ref")) + '</p>'
    publication += '<p>Publication status: ' + e(patch.get("publication_status") or "not published") + '</p>'
    if patch.get("publication_status") == "published":
        publication += '<p>Published image: <strong>' + e(patch.get("patched_image_ref")) + '</strong><br>Registry manifest digest: ' + e(patch.get("published_digest") or "not recorded (legacy)") + '<br>Published at: ' + e(patch.get("published_at")) + ' UTC</p>'
    publication += '<p class="muted">' + ("Scope: OS and application dependencies, all fix statuses. Absence of a finding is not proof of remediation or security." if verified_pair else "Legacy or incomplete scan evidence: comparison and recommendation are not verified. Run a new scan.") + '</p></section>'
    report = (
        banner + publication +
        '<div class="summary">' + cards + "</div>" +
        '<section><div class="section-title"><h2>What changed?</h2><p>Same image pipeline · initial scan vs patched rescan</p></div>'
        + bars(scans, original, patched) + changes + "</section>" +
        '<section><div class="section-title"><h2>Post-fix recommendation</h2><p>Advisory only — never a pass/fail gate</p></div>'
        + recommendation + "</section>" +
        ('<section><h2>Execution diagnostics</h2>' + "".join(errors) + "</section>" if errors else "") +
        '<section><div class="section-title"><h2>Evidence, without the clutter</h2>'
        '<p>Full unified finding table. Raw Trivy JSON and SBOM retain LOW.</p></div>' +
        '<p>Known fix before: ' + e(initial_fixable) + ' · No known fix before: ' + e(len(initial_rows)-initial_fixable) +
        ' · Known-fix findings no longer detected: ' + e(removed_fixable if verified_pair else None) +
        ' · Remaining with a known fix: ' + e(sum(bool(v["fixed"]) for v in final_rows) if verified_pair else None) +
        ' · Known-fix disappearance rate: ' + e(round(removed_fixable/initial_fixable*100, 2) if verified_pair and initial_fixable else None) + '%</p>' +
        '<p class="muted">UNKNOWN means Trivy did not assign a severity, not that the finding is harmless. Review vendor ratings/CVSS and advisory IDs; no automatic downgrade.</p>' +
        comparison_table(rows, verified_pair) + "</section>" +
        '<section><h2>Package Upgrade Summary</h2>' + package_upgrades(original, patched, verified_pair) + '</section>' +
        '<footer>Based on persisted Trivy findings. An absent or failed rescan is never reported as zero vulnerabilities. '
        'A recommendation is not a guarantee of security. Generated by AppSec Control Center.</footer>'
    )
    css = """
:root{font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;color:#18253d;background:#f3f7fc}
*{box-sizing:border-box}body{margin:0}main{max-width:1120px;margin:32px auto 80px;padding:0 24px}
.report-top{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;background:linear-gradient(125deg,#172f57,#156a83);
color:white;border-radius:20px;padding:30px;margin-bottom:18px;box-shadow:0 18px 32px #1c426126}
.report-top h1{font-size:26px;overflow-wrap:anywhere;margin:9px 0}.report-top p{font-size:12px;color:#d0eaf4}
.kicker{font-size:11px;font-weight:800;letter-spacing:.16em;color:#8be9d0}
.badge{border-radius:999px;padding:9px 14px;background:#ffffff30;color:white;font-size:12px;font-weight:700}
.summary,.changes{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:18px 0}
.changes{grid-template-columns:repeat(2,minmax(0,1fr))}
.metric{background:white;border:1px solid #e2ebf4;border-radius:14px;padding:20px;display:grid;gap:6px;box-shadow:0 8px 22px #243f5b0d}
.metric span{font-size:12px;color:#596d85}.metric strong{font-size:32px;line-height:1.15}.metric small{color:#758398;font-size:11px}
section{background:white;border:1px solid #e2ebf4;border-radius:17px;padding:26px;margin:18px 0}
.section-title{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:20px}
.section-title p{font-size:12px;color:#62748a;max-width:380px}h2{font-size:19px;margin:0 0 12px}
.legend{display:flex;gap:22px;color:#62748a;font-size:12px;margin:12px 0 24px}
.legend-before{font-weight:800}.legend-after{font-weight:800;color:#147c93}
.severity-row{display:grid;grid-template-columns:100px 1fr 115px;gap:12px;align-items:center;padding:10px 0;border-bottom:1px solid #edf1f7}
.severity-label{font-size:12px;font-weight:800}.bar-pair{display:grid;gap:6px}.bar-lane{height:13px;background:#f0f4f9;border-radius:10px;overflow:hidden}
.bar{height:100%;border-radius:9px}.bar.before{opacity:.4}.bar.after{opacity:1}
.bar-count{text-align:right;font-weight:750;font-size:14px}.bar-count span{color:#95a3b3;margin:0 5px}
.recommend{border-radius:13px;padding:18px 20px;line-height:1.55}
.recommend.good{background:#e6f8f0;color:#116142;border:1px solid #b7e4d0}
.recommend.bad{background:#fff0e9;color:#9b4c29;border:1px solid #f5ccb9}
.recommend.neutral{background:#eef5fc;color:#315b84;border:1px solid #cedff0}
.recommend p{margin:6px 0}.recommend ul{margin:10px 0 0}.issue{padding:12px;border-left:4px solid #e24e68;background:#fff0f3;margin:10px 0;border-radius:8px}
.issue p{white-space:pre-wrap;overflow-wrap:anywhere}
details{border:1px solid #e2eaf3;border-radius:12px;margin:10px 0;padding:16px}
summary{cursor:pointer;font-weight:750}details[open] summary{margin-bottom:12px}
.table-scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:12px}
th,td{padding:9px 11px;border-bottom:1px solid #edf1f5;text-align:left}th{background:#f6f9fc;white-space:nowrap}
.finding-state{display:inline-block;padding:5px 9px;border-radius:5px;font-weight:750;white-space:nowrap}.finding-state.fixed{color:#116142;background:#e6f8f0;border:1px solid #8fcea9}.finding-state.pending-state{color:#934a13;background:#fff1dd;border:1px solid #eec98e}
.muted,footer{font-size:12px;color:#6a788e;line-height:1.65}footer{padding:18px 8px}
@media(max-width:750px){.summary{grid-template-columns:repeat(2,minmax(0,1fr))}.severity-row{grid-template-columns:75px 1fr 80px}.report-top{flex-direction:column}.section-title{display:block}}
@media print{body{background:white}main{margin:0;max-width:none}section,.metric{break-inside:avoid}}
"""
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AppSec · Consolidated Image Report</title><style>' + css + '</style></head><body><main>' + report + '</main></body></html>'
