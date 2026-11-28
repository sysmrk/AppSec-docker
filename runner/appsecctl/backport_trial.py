"""Opt-in local candidate trials. Never authorize publication."""
import os
import re
import subprocess
from . import apt_optimization as apt, binary_discovery as binary, native_apt, fix_discovery as vendor
from . import independent_scan, remediation_audit as audit, candidate_review, job_watch

def enabled():
    return os.getenv("APPSEC_V4_BACKPORT_TRIAL","false").lower()=="true"

def select(plan,catalog):
    if catalog.get("status")!="completed" or not catalog.get("vendor_snapshot_sha256") or catalog.get("mirror")!=plan["mirror"]:
        return None
    groups={}
    for c in catalog.get("candidates") or []:
        groups.setdefault(c["installed_source"],[]).append(c)
    ranked=[]
    for source,rows in groups.items():
        sim=(catalog.get("simulations") or {}).get(source) or {}
        if sim.get("status")!="existing_package_upgrades_only" or any(
            c.get("status")!="signed_binary_found" or c.get("security_status")=="UPSTREAM_REGRESSION_LEAD" or
            c.get("source_package")!=source or not re.fullmatch(r"[a-f0-9]{64}",c.get("sha256") or "") for c in rows):
            continue
        if source=="curl" and (catalog.get("curl_upstream_review") or {}).get("status")!="completed":
            continue
        updates={c["package"]:{"before":c["before"],"after":c["candidate"]} for c in rows}
        if updates!=sim.get("changes") or any(n in plan["updates"] for n in updates):
            continue
        if any(n not in plan["inventory"] or plan["inventory"][n]["version"]!=u["before"]
               or not apt.PKG.fullmatch(n) or not native_apt.VERSION.fullmatch(u["after"])
               or not vendor.ge(u["after"],u["before"]) or vendor.ge(u["before"],u["after"])
               for n,u in updates.items()):
            continue
        leads=sum(len(c.get("threshold_leads") or []) for c in rows)
        if leads:
            ranked.append((-leads,source,updates,sorted(c["sha256"] for c in rows)))
    if not ranked:
        return None
    _,source,updates,hashes=sorted(ranked,key=lambda x:(x[0],x[1]))[0]
    return {"source":source,"updates":updates,"required_hashes":hashes}

def archive_script(release):
    if release not in ("bookworm","trixie"):
        raise ValueError("Invalid release")
    prefix=binary.PROBE.split('apt-cache madison "$@"',1)[0]
    return 'main=$1; security=$2; shift 2\nset -- "$main" "$security" '+release+' "$@"\n'+prefix+r'''
: > "$work/expected"
for pin do
    name=${pin%%=*}
    ver=${pin#*=}
    old=$(dpkg-query -W -f='${Version}' "$name")
    dpkg --compare-versions "$old" lt "$ver"
    selection=$(dpkg --get-selections "$name")
    if printf '%s\n' "$selection" | grep -Eq '[[:space:]]hold$'; then exit 23; fi
    printf '%s=%s\n' "${name%:amd64}" "$ver" >> "$work/expected"
done
sort "$work/expected" -o "$work/expected"
apt-get -s --no-remove --no-install-recommends install "$@" > "$work/sim"
awk '/^Inst /{
    if($3 !~ /^\[/ || $4 !~ /^\(/)exit 1;
    p=$2;sub(/:amd64$/,"",p);v=$4;sub(/^\(/,"",v);print p "=" v
} /^Remv |^Purg /{exit 1}' "$work/sim" > "$work/actual"
sort "$work/actual" -o "$work/actual"
cmp "$work/expected" "$work/actual"
grep -Eq '^[0-9]+ upgraded, 0 newly installed, 0 to remove and [0-9]+ not upgraded\.$' "$work/sim"
mkdir -p /tmp/appsec-download
cd /tmp/appsec-download
apt-get download "$@"
'''

def gate(reports,ind_a,ind_b):
    comparison=audit.analyze({"scans":reports},benchmark=True)
    a,b=[r["raw_report"] for r in reports]
    ca,cb=candidate_review.counts(a),candidate_review.counts(b)
    def inventory(report):
        return sorted((t["Class"],t.get("Type") or "",audit.scan_evidence.stable_target(t["Target"]),
                       tuple(sorted(p["Name"] for p in t.get("Packages") or []))) for t in report["Results"])
    diff=independent_scan.compare(ind_a,ind_b)
    blockers=[]
    if comparison["comparison"]!="benchmark_observed" or comparison.get("introduced")!=0:
        blockers.append("trivy_new_or_unverified_findings")
    if inventory(a)!=inventory(b) or any(v.get("coverage_unknown") for v in comparison["cohorts"].values()):
        blockers.append("inventory_coverage_changed")
    if any(g.get("observation")=="no_longer_detected_package_not_in_inventory" for g in comparison["groups"]):
        blockers.append("finding_package_missing")
    if any(cb[s]>ca[s] for s in ca):
        blockers.append("trivy_severity_regression")
    if diff.get("status")!="observed" or diff.get("introduced_count")!=0:
        blockers.append("independent_new_or_unverified_findings")
    elif ind_a.get("package_types")!=ind_b.get("package_types") or any((ind_b.get("severity") or {}).get(s,0)>(ind_a.get("severity") or {}).get(s,0)
             for s in set(ind_a.get("severity") or {})|set(ind_b.get("severity") or {})):
        blockers.append("independent_coverage_or_severity_regression")
    tr=sum(ca.values())-sum(cb.values())
    gr=(diff.get("before",0)-diff.get("after",0)) if diff.get("status")=="observed" else 0
    if tr<=0 and gr<=0:
        blockers.append("no_incremental_reduction")
    return {"status":"rejected" if blockers else "selected_local_candidate","blockers":blockers,
            "trivy_before":ca,"trivy_after":cb,"trivy_net_reduction":tr,
            "independent_comparison":diff,"grype_net_reduction":gr,
            "publication_authorized":False,"functional_test_passed":False}

def cleanup(candidate):
    if candidate:
        subprocess.run(["docker","image","rm",candidate["candidate"]],check=False,timeout=30,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

def attempt(plan,report,catalog,stable,authorized):
    if not enabled():
        return stable,{"status":"disabled"}
    if not independent_scan.enabled():
        return stable,{"status":"blocked","message":"Independent scanning required"}
    chosen=select(plan,catalog)
    if not chosen or plan["mirror"] not in authorized:
        return stable,{"status":"not_attempted","message":"No eligible signed source group or approved mirror"}
    combined={**plan,"updates":{**plan["updates"],**chosen["updates"]}}
    combined["plan_sha256"]=apt.plan_digest(combined)
    trial=None
    accepted=False
    try:
        job_watch.emit("backport_trial")
        release=vendor.RELEASES[str(report["Metadata"]["OS"]["Name"]).split(".")[0]]
        trial=native_apt._build_exact(combined,generic=True,archive_script=archive_script(release),
                                      required_hashes=chosen["required_hashes"])
        baseline=stable["candidate_image_id"] if stable else plan["image_id"]
        from .optimization import offline_compare
        reports,hashes,scanner=offline_compare([baseline,trial["candidate_image_id"]],report["_appsec"]["scanner_image"])
        ind_a,_,_=independent_scan.scan(baseline,reports[0]["raw_report"])
        ind_b,_,_=independent_scan.scan(trial["candidate_image_id"],reports[1]["raw_report"])
        result=gate(reports,ind_a,ind_b)
        result.update(source=chosen["source"],updates=chosen["updates"],trivy_db_files_sha256=hashes,
                      trivy_image_id=scanner,independent_db_files_sha256=ind_a.get("db_files_sha256"),
                      baseline_image_id=baseline,trial_image_id=trial["candidate_image_id"],
                      trial_plan_sha256=combined["plan_sha256"])
        job_watch.checkpoint()
        if result["status"]=="selected_local_candidate":
            accepted=True
            return trial,result
        return stable,result
    except (ValueError,RuntimeError,OSError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        from .workflow_control import StopRequested
        from .errors import safe_message
        if isinstance(exc,StopRequested):
            raise
        return stable,{"status":"rejected","source":chosen["source"],"message":safe_message(exc,"patch_build")}
    finally:
        if trial and not accepted:
            cleanup(trial)
