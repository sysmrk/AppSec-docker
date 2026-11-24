"""A single, self-contained, accessible Before/After pipeline report.

The report is regenerated at the same URL after patch/rescan. All counts come
from persisted Trivy scan rows and scan_diff records, never synthetic data.
"""
from __future__ import annotations

from html import escape
from typing import Any


SEVERITIES = (("CRITICAL", "critical_count", "#d94362"),
              ("HIGH", "high_count", "#ef923c"),
              ("MEDIUM", "medium_count", "#e5bd56"),
              ("LOW", "low_count", "#35a58a"),
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
                "severity": v.get("Severity"),
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


def findings_table(title: str, scan: dict | None) -> str:
    items = findings(scan)
    if not scan or scan.get("status") != "success":
        status = scan.get("status", "not yet available") if scan else "not yet available"
        return '<details><summary>' + e(title) + ' — ' + e(status) + ' (no verified results)</summary></details>'
    rows = "".join(
        "<tr><td>" + e(v["cve"]) + "</td><td><b>" + e(v["severity"]) + "</b></td>"
        "<td>" + e(v["package"]) + "</td><td>" + e(v["installed"]) + "</td><td>" +
        e(v["fixed"] or "No known fix") + "</td><td>" + e(v["target"]) + "</td></tr>"
        for v in items[:250]
    )
    note = ("Showing first 250 of " + str(len(items)) + " findings." if len(items) > 250 else
            "All " + str(len(items)) + " recorded vulnerability findings shown.")
    return ('<details><summary>' + e(title) + " · " + str(len(items)) +
            ' findings</summary><div class="table-scroll"><table><thead><tr>'
            '<th>CVE</th><th>Severity</th><th>Package</th><th>Installed</th><th>Fix version</th><th>Target</th>'
            "</tr></thead><tbody>" + rows + "</tbody></table></div><p class='muted'>" + note + "</p></details>")


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
    cards = (metric("Initial scan", original_total, "Vulnerabilities before patch")
             + metric("After patch", patched_total, "Only real completed rescans")
             + metric("Fixed", number(latest_diff.get("fixed_count")) if latest_diff else None, "No longer detected (not proof of remediation)")
             + metric("Introduced", number(latest_diff.get("introduced_count")) if latest_diff else None, "Newly detected"))
    changes = ""
    if latest_diff:
        changes = ('<div class="changes">' +
                   metric("Remaining", number(latest_diff.get("remaining_count")), "Still present after patch") +
                   metric("Net reduction", (original_total - patched_total) if original_total is not None and patched_total is not None else None,
                          "Initial minus final, all severities") + "</div>")
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
              badge(p.get("status") or "queued", "neutral") + "</div>")
    patch = (payload.get("patches") or [{}])[-1]
    publication = '<section><h2>Image identity and publication</h2>'
    for label, scan in (("Original scan", original), ("Patched rescan", patched)):
        evidence = (scan.get("raw_report") or {}).get("_appsec") or {} if scan else {}
        publication += '<p><strong>' + e(label) + '</strong>: ' + e(scan.get("image_ref") if scan else None) + '<br>Scan ID: ' + e(scan.get("id") if scan else None) + '<br>Image ID: ' + e(evidence.get("image_id")) + '<br>OS packages inspected: ' + e(evidence.get("os_package_count")) + '<br>Application packages inspected: ' + e(evidence.get("application_package_count")) + '<br>Finished: ' + e(scan.get("finished_at") if scan else None) + '</p>'
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
        '<p>Expand only the scan you need. Underlying Trivy JSON and CycloneDX SBOM remain separate raw artifacts.</p></div>' +
        findings_table("Initial vulnerabilities", original) +
        findings_table("After-patch vulnerabilities", patched) + "</section>" +
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
.muted,footer{font-size:12px;color:#6a788e;line-height:1.65}footer{padding:18px 8px}
@media(max-width:750px){.summary{grid-template-columns:repeat(2,minmax(0,1fr))}.severity-row{grid-template-columns:75px 1fr 80px}.report-top{flex-direction:column}.section-title{display:block}}
@media print{body{background:white}main{margin:0;max-width:none}section,.metric{break-inside:avoid}}
"""
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AppSec · Consolidated Image Report</title><style>' + css + '</style></head><body><main>' + report + '</main></body></html>'
