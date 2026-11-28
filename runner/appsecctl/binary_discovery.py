"""Read-only official Debian Backports binary and dependency review.
No binary installation, source compilation, or automatic approval.
Only the existing trusted local-image pilot is supported.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import os
import re
import subprocess
import time
from uuid import uuid4
from . import apt_optimization as apt, fix_discovery as vendor, native_apt, upstream_curl, job_watch

PROBE=r'''
export LC_ALL=C
. /etc/os-release
test "$ID" = debian
test "$VERSION_CODENAME" = "$3"
case "$VERSION_CODENAME" in bookworm|trixie) ;; *) exit 21;; esac
test -z "$(dpkg --print-foreign-architectures)"
key=/usr/share/keyrings/debian-archive-keyring.pgp
test -f "$key" || key=/usr/share/keyrings/debian-archive-keyring.gpg
test -f "$key"
main=$1; security=$2; suite=$3; shift 3
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
chmod 755 "$work"
mkdir "$work/empty" "$work/lists" "$work/cache"
printf 'deb [signed-by=%s] %s %s main\ndeb [signed-by=%s] %s %s-updates main\ndeb [signed-by=%s] %s %s-security main\ndeb [signed-by=%s] %s %s-backports main\n' "$key" "$main" "$suite" "$key" "$main" "$suite" "$key" "$security" "$suite" "$key" "$main" "$suite" > "$work/sources.list"
cat > "$work/apt.conf" <<EOF
Dir::Etc::parts "$work/empty";
Dir::Etc::main "/dev/null";
Dir::Etc::sourcelist "$work/sources.list";
Dir::Etc::sourceparts "$work/empty";
Dir::Etc::preferences "/dev/null";
Dir::Etc::preferencesparts "$work/empty";
Dir::State::lists "$work/lists";
Dir::Cache "$work/cache";
Acquire::Languages "none";
Acquire::Retries "1";
Acquire::https::Timeout "30";
Acquire::https::AllowRedirect "false";
Acquire::http::AllowRedirect "false";
Acquire::Check-Valid-Until "true";
Acquire::AllowInsecureRepositories "false";
Acquire::https::Verify-Peer "true";
Acquire::https::Verify-Host "true";
APT::Get::AllowUnauthenticated "false";
APT::Update::Error-Mode "any";
EOF
export APT_CONFIG="$work/apt.conf"
apt-get update >&2
apt-cache madison "$@" > "$work/madison"
awk -F '|' -v origin="$main" -v suite="$suite-backports/main" '
function trim(x){gsub(/^[[:space:]]+|[[:space:]]+$/,"",x);return x}
NF==3 {s=trim($3);n=split(s,a,/[[:space:]]+/);
if(n==4 && (a[1]==origin || a[1]==origin "/") && a[2]==suite &&
(a[3]=="amd64" || a[3]=="all") && a[4]=="Packages")
print trim($1),trim($2)}' "$work/madison" > "$work/versions"
: > "$work/pins"
dpkg --get-selections | awk '$2=="hold"{print "@@HOLD\t"$1}'
count=0
for name do
  bare=${name%%:*}
  old=$(dpkg-query -W -f='${Version}' "$name")
  src=$(dpkg-query -W -f='${source:Package}' "$name")
  srcver=$(dpkg-query -W -f='${source:Version}' "$name")
  best=
  for ver in $(awk -v p="$name" -v b="$bare" '$1==p || $1==b {print $2}' "$work/versions"); do
    if dpkg --compare-versions "$ver" gt "$old" &&
       { test -z "$best" || dpkg --compare-versions "$ver" gt "$best"; }; then best=$ver; fi
  done
  test -n "$best" || continue
  count=$((count+1))
  if test "$count" -gt 256; then echo '@@LIMIT'; break; fi
  printf '@@PACKAGE\t%s\t%s\t%s\t%s\t%s\n' "$name" "$old" "$src" "$srcver" "$best"
  apt-cache show "$name=$best" > "$work/show"
  awk '/^(Package|Version|Architecture|Source|SHA256|Size|Filename): /{print}
       /^$/{print ""}' "$work/show"
  echo '@@ENDPACKAGE'
  printf '%s %s=%s\n' "$src" "$name" "$best" >> "$work/pins"
done
groups=0
for src in $(awk '{print $1}' "$work/pins" | sort -u); do
  groups=$((groups+1))
  if test "$groups" -gt 24; then echo '@@SIMLIMIT'; break; fi
  printf '@@SIM\t%s\n' "$src"
  set -- $(awk -v s="$src" '$1==s{print $2}' "$work/pins")
  if apt-get -s --no-remove --no-install-recommends install "$@" > "$work/sim" 2>&1; then
    echo '@@EXIT 0'
  else
    echo '@@EXIT 1'
  fi
  cat "$work/sim"
  echo '@@ENDSIM'
done
echo '@@COMPLETE'
'''

def metadata(text,name,version):
    records=set()
    for block in re.split(r"\n\s*\n",text.strip()):
        fields={}
        for line in block.splitlines():
            k,sep,v=line.partition(": ")
            if not sep or k in fields:
                raise ValueError("Malformed archive metadata")
            fields[k]=v
        if fields.get("Package")!=name.split(":")[0] or fields.get("Version")!=version:
            continue
        arch=fields.get("Architecture")
        if arch not in ("amd64","all") or (":" in name and arch!=name.split(":")[1]):
            continue
        source=fields.get("Source",fields["Package"])
        match=re.fullmatch(r"([a-z0-9][a-z0-9+.-]*)(?: \(([^()]+)\))?",source)
        digest=fields.get("SHA256","")
        filename=fields.get("Filename","")
        size=fields.get("Size","")
        if not match or not re.fullmatch(r"[0-9a-f]{64}",digest) or not re.fullmatch(r"pool/[A-Za-z0-9+./_~%-]+\.deb",filename) or ".." in filename.split("/") or not size.isdigit() or not 0<int(size)<2**40:
            continue
        sv=match[2] or version
        if native_apt.VERSION.fullmatch(sv):
            records.add((arch,match[1],sv,digest,filename,int(size)))
    if len(records)!=1:
        raise ValueError("Exact archive metadata missing or ambiguous")
    return dict(zip(("architecture","source_package","source_version","sha256","filename","size"),next(iter(records))))

def simulation(text,exit_code,inventory,pins,holds):
    counts=re.findall(r"^(\d+) upgraded, (\d+) newly installed, (\d+) to remove and (\d+) not upgraded\.$",text,re.M)
    result={"status":"dependency_conflict","updates":None,"additions":None,"removals":None,"not_upgraded":None}
    if len(counts)==1:
        result.update(zip(("updates","additions","removals","not_upgraded"),map(int,counts[0])))
    if exit_code or len(counts)!=1:
        return result
    changes={}
    for line in text.splitlines():
        if line.startswith(("Remv ","Purg ")):
            result["status"]="removal_blocked"
            return result
        if not line.startswith("Inst "):
            continue
        m=re.fullmatch(r"Inst ([a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?)(?: \[([^\]]+)\])? \(([^ ]+)(?: .*)?\)",line)
        if not m or not native_apt.VERSION.fullmatch(m[3]):
            result["status"]="simulation_unverified"
            return result
        try:
            name=apt.resolve(m[1],inventory)
        except ValueError:
            name=m[1]
            if m[2] or any(n.split(":")[0]==name.split(":")[0] for n in inventory):
                result["status"]="simulation_unverified"
                return result
        old=inventory.get(name,{}).get("version")
        if name in changes or old!=m[2]:
            result["status"]="simulation_unverified"
            return result
        if old and (not vendor.ge(m[3],old) or vendor.ge(old,m[3])):
            result["status"]="downgrade_or_reinstall_blocked"
            return result
        if name.split(":")[0] in holds:
            result["status"]="held_package_blocked"
            return result
        changes[name]={"before":old,"after":m[3]}
    result["changes"]=changes
    if result["removals"]:
        result["status"]="removal_blocked"
    elif len(changes)!=result["updates"]+result["additions"] or sum(v["before"] is None for v in changes.values())!=result["additions"] or any(changes.get(n,{}).get("after")!=v for n,v in pins.items()):
        result["status"]="simulation_unverified"
    elif result["additions"]:
        result["status"]="dependency_additions_not_authorized"
    else:
        result["status"]="existing_package_upgrades_only"
    return result

def parse(output,inventory,findings):
    lines=output.splitlines()
    if not lines or lines[-1]!="@@COMPLETE":
        raise ValueError("Incomplete Backports probe")
    candidates=[]
    simulations={}
    holds=set()
    limited=False
    i=0
    while i<len(lines)-1:
        line=lines[i];i+=1
        if line in ("@@LIMIT","@@SIMLIMIT"):
            limited=True
        elif line.startswith("@@HOLD\t"):
            holds.add(line.split("\t",1)[1].split(":")[0])
        elif line.startswith("@@PACKAGE\t"):
            fields=line.split("\t")
            if len(fields)!=6:
                raise ValueError("Malformed candidate marker")
            _,name,old,src,srcver,new=fields
            end=lines.index("@@ENDPACKAGE",i)
            block="\n".join(lines[i:end]);i=end+1
            if (name not in inventory or old!=inventory[name]["version"] or
                not vendor.NAME.fullmatch(src) or not native_apt.VERSION.fullmatch(srcver) or
                not native_apt.VERSION.fullmatch(new) or vendor.ge(old,new) or
                any(c["package"]==name for c in candidates)):
                raise ValueError("Candidate inventory identity mismatch")
            candidate={"package":name,"before":old,"candidate":new,"installed_source":src,"installed_source_version":srcver}
            try:
                candidate.update(metadata(block,name,new))
                if candidate["source_package"]!=src:
                    raise ValueError("Source package identity changed")
                related=[v for v in findings if v.get("scanner")=="trivy" and v.get("source_package")==src
                    and v.get("installed_source_version")==srcver and
                    v.get("package","").split(":")[0]==name.split(":")[0] and v.get("installed_binary_version")==old]
                leads=[]
                for v in related:
                    thresholds={k:x["fixed_version"] for k,x in (v.get("newer_releases") or {}).items()
                        if isinstance(x.get("fixed_version"),str) and native_apt.VERSION.fullmatch(x["fixed_version"])
                        and vendor.ge(candidate["source_version"],x["fixed_version"])}
                    if thresholds:
                        leads.append({"id":v["id"],"newer_release_thresholds":thresholds})
                candidate.update(status="signed_binary_found",threshold_leads=leads,
                                 matching_original_findings=len(related),security_status="unverified")
            except ValueError:
                candidate.update(status="binary_identity_unverified",security_status="unverified",threshold_leads=[])
            candidates.append(candidate)
        elif line.startswith("@@SIM\t"):
            src=line.split("\t",1)[1]
            if src in simulations or not vendor.NAME.fullmatch(src) or lines[i] not in ("@@EXIT 0","@@EXIT 1"):
                raise ValueError("Malformed simulation marker")
            exit_code=int(lines[i][-1]);i+=1
            end=lines.index("@@ENDSIM",i)
            pins={c["package"]:c["candidate"] for c in candidates if c["installed_source"]==src}
            if not pins:
                raise ValueError("Simulation without candidate")
            simulations[src]=simulation("\n".join(lines[i:end]),exit_code,inventory,pins,holds)
            i=end+1
        else:
            raise ValueError("Unexpected Backports probe output")
    if len(candidates)>256 or len(simulations)>24:
        raise ValueError("Probe exceeds candidate limits")
    for c in candidates:
        c["dependency_status"]=simulations.get(c["installed_source"],{}).get("status","not_simulated")
        c["decision"]="REVIEW_REQUIRED"
    return {"status":"partial" if limited else "completed","candidates":candidates,
            "simulations":simulations,"candidate_count":len(candidates),
            "threshold_lead_count":sum(len(c["threshold_leads"]) for c in candidates),
            "automatic_selection_count":0,"publication_authorized":False}

def curl_range_review(result,findings,image):
    rows=[c for c in result["candidates"] if c.get("status")=="signed_binary_found" and c.get("source_package")=="curl"]
    if not rows:
        return
    try:
        with Path("/vendor-snapshots/curl-vuln.json").open("rb") as stream:
            if not 0<=time.time()-os.fstat(stream.fileno()).st_mtime<6*3600:
                raise ValueError("stale")
            data=stream.read(16*1024*1024+1)
        if len(data)>16*1024*1024:
            raise ValueError("oversized")
        feed=json.loads(data)
        old={c["installed_source_version"] for c in rows}
        new={c["source_version"] for c in rows}
        if len(old)!=1 or len(new)!=1:
            raise ValueError("ambiguous")
        a,b=(re.fullmatch(r"(\d+\.\d+\.\d+)-[A-Za-z0-9.+~]+",next(iter(x))) for x in (old,new))
        if not a or not b:
            raise ValueError("unsupported")
        review=upstream_curl.audit({"schema":"appsec.fix-research/v1","image_id":image,"findings":findings},feed,a[1],b[1])
        result["curl_upstream_review"]={"status":"completed","snapshot_sha256":hashlib.sha256(data).hexdigest(),
            "original_upstream":a[1],"candidate_upstream":b[1],
            "finding_breakdown":review["finding_breakdown"],"full_feed_review":review["full_feed_review"],
            "new_exposure_ids":[v["id"] for v in review["new_upstream_exposure_leads"]]}
        if review["new_upstream_exposure_leads"]:
            for c in rows:
                c["security_status"]="UPSTREAM_REGRESSION_LEAD"
    except (OSError,ValueError,TypeError,KeyError):
        result["curl_upstream_review"]={"status":"unavailable","message":"Fresh compatible optional host curl feed required"}

def discover(image,report,plan):
    inventory=plan["inventory"]
    if len(inventory)>2000 or any(not apt.PKG.fullmatch(n) or (":" in n and not n.endswith(":amd64")) for n in inventory):
        raise ValueError("Unsupported inventory size or architecture")
    mirror=plan["mirror"]
    release=vendor.RELEASES[str(report["Metadata"]["OS"]["Name"]).split(".")[0]]
    main,security=apt.MIRRORS[mirror]
    name="appsec-binary-probe-"+uuid4().hex
    job_watch.emit("binary_discovery")
    try:
        output=apt.run(["docker","run","--rm","--name",name,"--pull=never","--user","0:0",
             "--security-opt","no-new-privileges:true","--pids-limit","128","--memory","1g",
             "--entrypoint","/bin/sh",image,"-ec",PROBE,"probe",main,security,release,*sorted(inventory)],420)
        evidence=(report.get("_appsec") or {}).get("fix_discovery") or {}
        findings=evidence.get("findings") or []
        result=parse(output,inventory,findings)
        result.update(mirror=mirror,suite=release+"-backports",repository=main,
                      vendor_snapshot_sha256=evidence.get("snapshot_sha256"),
                      message="Read-only official Backports review. Version thresholds are leads, not security proof. Stable plan remains unchanged.")
        curl_range_review(result,findings,image)
        job_watch.emit("binary_candidates",result["candidate_count"])
        return result
    finally:
        subprocess.run(["docker","rm","-f",name],check=False,timeout=30,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
