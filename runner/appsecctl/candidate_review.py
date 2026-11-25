"""Review frozen benchmark candidates; never promote an image.

Consumes local reports produced by scripts/v3-benchmark.py. Recomputes
comparisons; does not infer functional compatibility from CVE counts.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

from . import remediation_audit as audit

SEVERITIES=("CRITICAL","HIGH","UNKNOWN","MEDIUM","LOW")


def load(root, filename):
    return json.loads((root / filename).read_text(encoding="utf-8"))


def scan(report, phase, label):
    return {"id":label,"phase":phase,"status":"success","raw_report":report}


def counts(report):
    totals=Counter()
    for target in report["Results"]:
        for v in target.get("Vulnerabilities") or []:
            sev=str(v.get("Severity") or "UNKNOWN").upper()
            totals[sev if sev in SEVERITIES else "UNKNOWN"]+=1
    return {s:totals[s] for s in SEVERITIES}


def package_versions(report):
    rows={}
    for target in report["Results"]:
        if target["Class"]!="os-pkgs":
            continue
        for pkg in target.get("Packages") or []:
            if pkg.get("Name") and pkg.get("Version"):
                rows.setdefault(pkg["Name"],set()).add(pkg["Version"])
    return rows


def review(root):
    manifest=load(root,"manifest.json")
    if manifest.get("schema")!="appsec.benchmark/v1" or not manifest.get("database_files_sha256"):
        raise ValueError("Frozen benchmark manifest required")
    images=manifest["images"]
    if not 2<=len(images)<=13 or len({i["id"] for i in images})!=len(images):
        raise ValueError("Invalid benchmark image list")
    scanner=manifest["scanner_image_id"]
    original=load(root,"original.json")
    before=scan(original,"original","original")
    if not audit.verified(before) or original["_appsec"]["image_id"]!=images[0]["id"] or original["_appsec"].get("scanner_image")!=scanner:
        raise ValueError("Original image/scanner evidence mismatch")
    base_counts=counts(original)
    base_pkgs=package_versions(original)
    candidates=[]
    for idx, item in enumerate(images[1:],1):
        label="candidate-"+str(idx)
        raw=load(root,label+".json")
        saved=load(root,label+"-comparison.json")
        after=scan(raw,"patched",label)
        if (not audit.verified(after) or raw["_appsec"]["image_id"]!=item["id"] or
                raw["_appsec"].get("scanner_image")!=scanner or
                saved.get("frozen_db_content_verified") is not True or
                saved.get("scanner_image_id")!=scanner):
            raise ValueError("Candidate benchmark evidence mismatch: "+label)
        comparison=audit.analyze({"scans":[before,after]},benchmark=True)
        if comparison["comparison"]!="benchmark_observed":
            raise ValueError("Unverified candidate comparison")
        if any(saved.get(k)!=comparison.get(k) for k in ("cohorts","introduced","original_image_id","patched_image_id")):
            raise ValueError("Saved comparison differs from raw evidence")
        after_counts=counts(raw)
        pkgs=package_versions(raw)
        removed=sorted(set(base_pkgs)-set(pkgs))
        changed=sorted(p for p in set(base_pkgs)&set(pkgs) if base_pkgs[p]!=pkgs[p])
        added=sorted(set(pkgs)-set(base_pkgs))
        absent_on_removed=0
        for g in comparison["groups"]:
            if g["class"]=="os-pkgs" and g["package"] in removed:
                absent_on_removed+=g["no_longer_detected"] or 0
        unknown=sum(v["coverage_unknown"] or 0 for v in comparison["cohorts"].values())
        blockers=[]
        if unknown:
            blockers.append("coverage_unknown")
        if comparison["introduced"]:
            blockers.append("new_findings")
        if any(after_counts[s]>base_counts[s] for s in ("CRITICAL","HIGH","UNKNOWN")):
            blockers.append("severity_regression")
        if sum(after_counts.values())>=sum(base_counts.values()):
            blockers.append("no_net_reduction")
        candidates.append({"image_id":item["id"],"reference":item["ref"],"severity":after_counts,
                           "total_findings":sum(after_counts.values()),"net_reduction":sum(base_counts.values())-sum(after_counts.values()),
                           "removed_package_names":removed,"added_package_names":added,"changed_package_names":changed,
                           "absent_findings_on_removed_package_names":absent_on_removed,
                           "introduced":comparison["introduced"],"coverage_unknown":unknown,
                           "comparison_blockers":blockers,"functional_test_verified":False,"publication_authorized":False})
    # Conservative ranking for review: Critical, High, Unknown, Medium, Low.
    # Unknown is prioritized rather than silently treating it as Low.
    ordered=sorted(candidates,key=lambda c:(bool(c["comparison_blockers"]),*(c["severity"][s] for s in SEVERITIES),
                                            len(c["removed_package_names"]),c["image_id"]))
    for idx,c in enumerate(ordered,1):
        c["review_rank"]=idx if not c["comparison_blockers"] else None
    return {"schema":"appsec.candidate-review/v1","original_image_id":images[0]["id"],
            "original_severity":base_counts,"original_total":sum(base_counts.values()),
            "scanner_image_id":scanner,"candidates":ordered,
            "preferred_for_review":next((c["image_id"] for c in ordered if not c["comparison_blockers"]),None),
            "publication_authorized":False,
            "limitations":["Local benchmark files are trusted operator inputs, not signed attestations.",
                           "Package-name absence is not proof of historical-layer erasure or functional compatibility.",
                           "Ranking is security-review ordering only; workload tests and approvals are still required."]}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--results",required=True,type=Path)
    args=p.parse_args(argv)
    try:
        print(json.dumps(review(args.results),indent=2))
    except (OSError,ValueError,KeyError,TypeError,RuntimeError) as exc:
        print("CANDIDATE_REVIEW_FAILED: "+str(exc)[:500],file=sys.stderr)
        return 1
    return 0


if __name__=="__main__":
    raise SystemExit(main())
