#!/usr/bin/env python3
"""V4 Plan A lab: one original scan, native APT,
optional prebuilt candidates, identical frozen DB, and local HTTP smoke checks.
No AppSec deployment, database, push, automatic promotion or runtime integration.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"runner"))
from appsecctl import benchmark as bench, apt_optimization as apt, native_apt, scan_evidence, remediation_audit as audit, candidate_review, v4_validation


def parse_timestamp(value):
    # Trivy writes RFC3339 with up to nine fractional digits. Python 3.10
    # accepts only three/six, so normalize explicitly to microseconds.
    value=re.sub(r"(\.\d{6})\d+(?=Z|[+-]\d{2}:\d{2}$)",r"\1",value)
    return datetime.fromisoformat(value.replace("Z","+00:00"))


def database_state(cache, now=None):
    data=json.loads((cache/"db/metadata.json").read_text())
    now=now or datetime.now(timezone.utc)
    updated=parse_timestamp(data["UpdatedAt"])
    due=parse_timestamp(data["NextUpdate"])
    if data.get("Version")!=2 or not updated<=now or not updated<due:
        raise ValueError("Invalid Trivy DB metadata")
    return {"updated_at":data["UpdatedAt"],"next_update":data["NextUpdate"],
            "age_hours":round((now-updated).total_seconds()/3600,3),"fresh":now<due}


def describe(image):
    row=apt.inspect(image)
    return {"image_id":image,"bytes":row["Size"],"os":row["Os"],"architecture":row["Architecture"]}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--original",required=True,help="Preloaded trusted Debian 12/13 Nginx image")
    p.add_argument("--scanner",required=True,help="Preloaded Trivy image")
    p.add_argument("--db-cache",required=True,type=Path,help="Prepared cache; stop all DB writers while copying")
    p.add_argument("--output",required=True,type=Path,help="New private evidence directory")
    p.add_argument("--mirror",action="append",choices=sorted(apt.MIRRORS),help="Approved Debian mirror priority; required for native APT")
    p.add_argument("--native-apt",action="store_true",help="Try same-release existing-package upgrades")
    p.add_argument("--remove",action="append",choices=apt.OPTIONAL,default=[],help=argparse.SUPPRESS)
    p.add_argument("--candidate",action="append",default=[],help="Preloaded external candidate (e.g. Copa or SlimToolkit); repeat")
    p.add_argument("--allow-overdue-db",action="store_true",help="Diagnostic only, up to 72 hours; cannot pass acceptance gate")
    p.add_argument("--http-path",default="/")
    p.add_argument("--http-port",type=int,default=80)
    p.add_argument("--timeout",type=int,default=1800,help="Per scanner command timeout")
    p.add_argument("--confirm-isolated-lab",action="store_true",required=True)
    args=p.parse_args(argv)
    if args.remove:
        p.error("V4 preservation policy: package removal is disabled")
    if not (args.native_apt or args.candidate):
        p.error("Select at least one candidate strategy")
    if args.native_apt and not args.mirror:
        p.error("--native-apt requires explicit --mirror")
    if len(args.candidate)>10 or not 1<=args.timeout<=86400:
        p.error("At most ten prebuilt candidates and a bounded scanner timeout")
    os.umask(0o077)
    image=scan_evidence.local_image_id(args.original)
    scanner=scan_evidence.local_image_id(args.scanner)
    cache=args.db_cache.resolve(strict=True)
    manifest=bench.snapshot_manifest(cache)
    state=database_state(cache)
    if state["age_hours"]>72 or (not state["fresh"] and not args.allow_overdue_db):
        p.error("Fresh Trivy DB required; --allow-overdue-db allows bounded diagnostic runs only")
    out=args.output.resolve()
    out.mkdir(mode=0o700,parents=True,exist_ok=False)
    results=[]
    candidates=[]
    started=time.monotonic()
    with tempfile.TemporaryDirectory(prefix="appsec-v4-frozen-") as tmp:
        frozen=Path(tmp)
        for folder in ("db","java-db"):
            if (cache/folder).is_dir():
                shutil.copytree(cache/folder,frozen/folder)
        if bench.snapshot_manifest(frozen)!=manifest or bench.snapshot_manifest(cache)!=manifest:
            raise RuntimeError("Source DB changed during snapshot")
        state=database_state(frozen)
        if state["age_hours"]>72 or (not state["fresh"] and not args.allow_overdue_db):
            raise RuntimeError("Frozen DB no longer within permitted age")
        # Save provenance immediately, including failed/incomplete lab runs.
        bench.write_json(out/"snapshot.json",{"scanner_image_id":scanner,"original_image_id":image,
                         "database_files_sha256":manifest,"database_state":state})
        t=time.monotonic()
        original=bench.scan_one(args.original,image,scanner,frozen,manifest,out,"original",args.timeout)
        raw=original["raw_report"]
        baseline={**describe(image),"scan_seconds":round(time.monotonic()-t,3),
                  "smoke":v4_validation.smoke(image,args.http_path,args.http_port)}
        bench.write_json(out/"baseline.json",baseline)
        if baseline["smoke"]["status"]!="passed":
            raise RuntimeError("Original workload smoke test failed; candidate validation cannot be meaningful")
        def attempt(name, operation):
            t=time.monotonic()
            try:
                record=operation()
                if record is None:
                    results.append({"engine":name,"status":"no_changes","seconds":round(time.monotonic()-t,3)})
                    return
                iid=scan_evidence.local_image_id(record["candidate"])
                if iid!=record["candidate_image_id"] or iid==image or iid in {c["candidate_image_id"] for c in candidates}:
                    raise RuntimeError("Candidate image identity changed, duplicate or unchanged")
                candidates.append({**record,"engine":name,"build_seconds":round(time.monotonic()-t,3)})
            except (ValueError,RuntimeError,OSError,subprocess.SubprocessError) as exc:
                # Do not copy raw subprocess output or command lines to public evidence.
                from appsecctl.errors import safe_detail
                raw=exc.stderr if isinstance(exc,(subprocess.CalledProcessError,subprocess.TimeoutExpired)) else str(exc)
                if isinstance(raw,bytes):
                    raw=raw.decode(errors="replace")
                # Prefer a concrete package-manager diagnostic over the final
                # BuildKit wrapper; strip credentials using existing helper.
                lines=[line for line in (raw or "").splitlines() if re.search(
                    r"(?:^|\s)(?:E:|dpkg: error:|dpkg: error processing|dependency problems)",line,re.I)]
                detail=safe_detail(lines[-1] if lines else raw)
                if not raw:
                    detail="Command failed; consult the preceding local build output"
                results.append({"engine":name,"status":"failed","error_type":type(exc).__name__,
                                "diagnostic":detail,"seconds":round(time.monotonic()-t,3)})
                print(name+" failed: "+detail,file=sys.stderr)
        def native():
            plan=native_apt.plan(image,raw,args.mirror)
            bench.write_json(out/"native-apt-plan.json",plan)
            if not plan["updates"]:
                return None
            return native_apt.build(plan,raw,plan["plan_sha256"],args.mirror)
        if args.native_apt:
            attempt("native_apt",native)
        for idx,ref in enumerate(args.candidate,1):
            attempt("prebuilt_"+str(idx),lambda ref=ref:{"candidate":ref,"candidate_image_id":scan_evidence.local_image_id(ref)})
        comparisons=[]
        images=[{"ref":args.original,"id":image}]
        for record in candidates:
            label="candidate-"+str(len(comparisons)+1)
            ref,iid=record["candidate"],record["candidate_image_id"]
            t=time.monotonic()
            candidate=bench.scan_one(ref,iid,scanner,frozen,manifest,out,label,args.timeout)
            comparison=audit.analyze({"scans":[original,candidate]},benchmark=True)
            if comparison["comparison"]!="benchmark_observed":
                raise RuntimeError("Benchmark comparison evidence unavailable")
            comparison.update(frozen_db_content_verified=True,scanner_image_id=scanner)
            bench.write_json(out/(label+"-comparison.json"),comparison)
            comparisons.append({"candidate":ref,"comparison_file":label+"-comparison.json","cohorts":comparison["cohorts"],"introduced":comparison["introduced"]})
            images.append({"ref":ref,"id":iid})
            test=v4_validation.smoke(iid,args.http_path,args.http_port)
            results.append({**record,**describe(iid),"status":"compared","scan_and_test_seconds":round(time.monotonic()-t,3),
                            "smoke":test,"smoke_matches_baseline":v4_validation.matches(baseline["smoke"],test)})
        bench.write_json(out/"manifest.json",{"schema":"appsec.benchmark/v1","scanner_image_id":scanner,
                         "database_files_sha256":manifest,"images":images,"database_state":state,
                         "scan_mode":"offline archive; OS and library; all severities"})
        bench.write_json(out/"summary.json",comparisons)
        review=candidate_review.review(out) if comparisons else {"candidates":[],"preferred_for_review":None}
        by_id={r["candidate_image_id"]:r for r in results if r["status"]=="compared"}
        eligible=[r["image_id"] for r in review["candidates"] if not r["comparison_blockers"]
                  and not r["removed_package_names"] and by_id[r["image_id"]]["smoke_matches_baseline"] and state["fresh"]]
        final={"schema":"appsec.v4-benchmark/v1","database":state,"baseline":baseline,"engines":results,
               "security_review":review,"lab_gate":"passed" if eligible else "no_verified_improvement",
               "eligible_for_further_workload_testing":eligible,"publication_authorized":False,
               "limitations":["HTTP 200 and identical body are a smoke test, not full workload validation.",
                              "Prebuilt candidates have no verified build lineage in this harness.",
                              "Removed package findings are not proof of historical layer erasure.",
                              "Overdue DB results are diagnostic only."],
               "seconds":round(time.monotonic()-started,3)}
        bench.write_json(out/"v4-result.json",final)
    print(out/"v4-result.json")
    return 0 if eligible else 2


if __name__=="__main__":
    sys.exit(main())
