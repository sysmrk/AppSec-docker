"""Operator-approved third-party APT discovery. No installation."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlsplit
from uuid import uuid4
from . import apt_optimization as apt, binary_discovery as binary, fix_discovery as vendor, native_apt
from .workflow_control import StopRequested

ROOT = Path("/vendor-snapshots")
NAME = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}")
DIGEST = re.compile(r"[a-f0-9]{64}")

def read_bounded(path, limit):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Invalid approval file")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if not data or len(data) > limit:
        raise ValueError("Invalid approval file size")
    return data

def validate(document):
    if not isinstance(document, dict) or set(document) != {"schema", "repositories"} or document["schema"] != "appsec.approved-binaries/v1":
        raise ValueError("Invalid approved repository schema")
    rows = document["repositories"]
    if not isinstance(rows, list) or len(rows) > 4:
        raise ValueError("At most four approved sources")
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or not {"id", "url", "suite", "component", "keyring_sha256", "packages"} <= set(row) or set(row) - {"id", "url", "suite", "component", "keyring_sha256", "packages", "advisory_sha256"}:
            raise ValueError("Invalid repository fields")
        if any(not isinstance(row[k], str) for k in ("id", "url", "suite", "component", "keyring_sha256")):
            raise ValueError("Invalid repository values")
        url = urlsplit(row["url"])
        if (not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}",row["id"]) or row["id"] in seen
            or row["suite"] not in ("bookworm","trixie") or not NAME.fullmatch(row["component"])
            or not DIGEST.fullmatch(row["keyring_sha256"])
            or not re.fullmatch(r"https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~-]+)*/?",row["url"])
            or not url.hostname or url.username or url.password or any(p in (".","..") for p in url.path.split("/"))):
            raise ValueError("Invalid repository identity, HTTPS endpoint or key hash")
        if "advisory_sha256" in row and (not isinstance(row["advisory_sha256"],str) or not DIGEST.fullmatch(row["advisory_sha256"])):
            raise ValueError("Invalid advisory snapshot digest")
        pkgs = row["packages"]
        if not isinstance(pkgs,list) or not 1<=len(pkgs)<=64 or any(not isinstance(n,str) or not NAME.fullmatch(n) for n in pkgs) or len(set(pkgs))!=len(pkgs):
            raise ValueError("Explicit package allowlist required")
        seen.add(row["id"])
    return rows

# Inherit isolated APT options, not the official repository configuration.
PROBE = binary.PROBE[:binary.PROBE.index('apt-cache madison "$@"')]
PROBE = PROBE.replace('key=/usr/share/keyrings/debian-archive-keyring.pgp\ntest -f "$key" || key=/usr/share/keyrings/debian-archive-keyring.gpg\ntest -f "$key"\n','')
PROBE = PROBE.replace('main=$1; security=$2; suite=$3; shift 3',
                      'main=$1; component=$2; suite=$3; shift 3\nkey=/tmp/appsec-vendor-key.gpg')
start = PROBE.index("printf 'deb ")
end = PROBE.index('cat > "$work/apt.conf"',start)
PROBE = PROBE[:start] + "printf 'deb [signed-by=%s] %s %s %s\\n' \"$key\" \"$main\" \"$suite\" \"$component\" > \"$work/sources.list\"\n" + PROBE[end:]
PROBE += r'''
: > "$work/pins"
dpkg --get-selections | awk '$2=="hold"{print "@@HOLD\t"$1}'
for name do
  old=$(dpkg-query -W -f='${Version}' "$name")
  src=$(dpkg-query -W -f='${source:Package}' "$name")
  srcver=$(dpkg-query -W -f='${source:Version}' "$name")
  best=
  apt-cache madison "$name" > "$work/madison"
  for ver in $(awk -F '|' -v origin="$main" -v suite="$suite/$component" '
  function trim(x){gsub(/^[[:space:]]+|[[:space:]]+$/,"",x);return x}
  NF==3 {n=split(trim($3),a,/[[:space:]]+/);
  if(n==4 && (a[1]==origin || a[1]==origin "/") && a[2]==suite &&
     (a[3]=="amd64" || a[3]=="all") && a[4]=="Packages") print trim($2)}' "$work/madison"); do
    if dpkg --compare-versions "$ver" gt "$old" &&
       { test -z "$best" || dpkg --compare-versions "$ver" gt "$best"; }; then best=$ver; fi
  done
  test -n "$best" || continue
  printf '@@PACKAGE\t%s\t%s\t%s\t%s\t%s\n' "$name" "$old" "$src" "$srcver" "$best"
  apt-cache show "$name=$best" > "$work/show"
  awk '/^(Package|Version|Architecture|Source|SHA256|Size|Filename): /{print} /^$/{print ""}' "$work/show"
  echo '@@ENDPACKAGE'
  printf '%s %s=%s\n' "$src" "$name" "$best" >> "$work/pins"
done
groups=0
for src in $(awk '{print $1}' "$work/pins" | sort -u); do
  groups=$((groups+1))
  if test "$groups" -gt 16; then echo '@@SIMLIMIT'; break; fi
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

def parse(output, inventory, allowed, findings=()):
    result=binary.parse(output,inventory,findings)
    rows=result["candidates"]
    if len(rows)>64 or len(result["simulations"])>16 or any(c["package"] not in allowed for c in rows):
        raise ValueError("External candidate scope exceeded")
    for source,sim in result["simulations"].items():
        expected={c["package"]:{"before":c["before"],"after":c["candidate"]}
                  for c in rows if c["installed_source"]==source}
        if sim["status"]=="existing_package_upgrades_only" and sim.get("changes")!=expected:
            sim["status"]="additional_upgrades_not_authorized"
    for c in rows:
        sim=result["simulations"].get(c["installed_source"],{})
        c["dependency_status"]=sim.get("status","not_simulated")
    return result

def advisories(data, row):
    """Operator-pinned assertions, not independent vendor authentication."""
    if hashlib.sha256(data).hexdigest()!=row.get("advisory_sha256"):
        raise ValueError("Advisory digest mismatch")
    doc=json.loads(data)
    if not isinstance(doc,dict) or set(doc)!={"schema","repository_id","suite","records"} or doc["schema"]!="appsec.external-advisories/v1" or doc["repository_id"]!=row["id"] or doc["suite"]!=row["suite"]:
        raise ValueError("Advisory scope mismatch")
    records=doc["records"]
    if not isinstance(records,list) or len(records)>2000:
        raise ValueError("Invalid advisory record count")
    out={}
    for record in records:
        if not isinstance(record,dict) or set(record)!={"package","version","architecture","archive_sha256","cve","advisory_url"} or any(not isinstance(v,str) for v in record.values()):
            raise ValueError("Invalid advisory record")
        url=urlsplit(record["advisory_url"])
        if (record["package"] not in row["packages"] or not native_apt.VERSION.fullmatch(record["version"]) or record["architecture"] not in ("amd64","all")
            or not DIGEST.fullmatch(record["archive_sha256"]) or not re.fullmatch(r"CVE-\d{4}-\d{4,}",record["cve"])
            or url.scheme!="https" or not url.hostname or url.username or url.password or len(record["advisory_url"])>2048
            or any(ord(ch)<33 or ord(ch)==127 for ch in record["advisory_url"])):
            raise ValueError("Invalid advisory identity")
        key=(record["package"],record["version"],record["architecture"],record["archive_sha256"],record["cve"])
        if key in out:
            raise ValueError("Duplicate advisory assertion")
        out[key]=record["advisory_url"]
    return out

def correlate(candidates, findings, assertions):
    for c in candidates:
        # Preserve original scanner evidence and match all available identities.
        related=sorted({v["id"] for v in findings if v.get("scanner")=="trivy"
            and v.get("source_package")==c["installed_source"]
            and v.get("installed_source_version")==c["installed_source_version"]
            and v.get("package","").split(":")[0]==c["package"].split(":")[0]
            and v.get("installed_binary_version")==c["before"]
            and isinstance(v.get("id"),str) and re.fullmatch(r"CVE-\d{4}-\d{4,}",v["id"])})
        matches=[]
        if c["status"]=="signed_binary_found":
            for cve in related:
                key=(c["package"].split(":")[0],c["candidate"],c["architecture"],c["sha256"],cve)
                if key in assertions:
                    matches.append({"id":cve,"advisory_url":assertions[key]})
        c["original_cve_ids"]=related
        c["operator_advisory_matches"]=matches
        c["security_status"]="operator_assertion_matched" if matches else "unverified"
        c["decision"]="REVIEW_REQUIRED"

def probe(image,row,inventory,root,findings=()):
    names=sorted(n for n in inventory if n.split(":")[0] in row["packages"] and (":" not in n or n.endswith(":amd64")))
    if not names:
        return {"id":row["id"],"status":"not_applicable","candidates":[]}
    if len(names)>64:
        raise ValueError("Package allowlist expands beyond probe bound")
    key=read_bounded(root/(row["id"]+".gpg"),1024*1024)
    if hashlib.sha256(key).hexdigest()!=row["keyring_sha256"]:
        raise ValueError("Approved keyring digest mismatch")
    name="appsec-vendor-probe-"+uuid4().hex
    try:
        with tempfile.TemporaryDirectory(prefix="appsec-vendor-key-") as tmp:
            path=Path(tmp)/"key.gpg"
            path.write_bytes(key)
            path.chmod(0o644)
            apt.run(["docker","create","--name",name,"--pull=never","--user","0:0",
                     "--security-opt","no-new-privileges:true","--pids-limit","128","--memory","1g",
                     "--entrypoint","/bin/sh",image,"-ec",PROBE,"probe",row["url"],row["component"],row["suite"],*names],60)
            apt.run(["docker","cp",str(path),name+":/tmp/appsec-vendor-key.gpg"],30)
            output=apt.run(["docker","start","-a",name],180)
            if apt.run(["docker","inspect","--format","{{.State.ExitCode}}",name]).strip()!="0":
                raise ValueError("Approved repository probe failed")
        parsed=parse(output,inventory,names,findings)
        assertions={}
        advisory_status="not_configured"
        if "advisory_sha256" in row:
            try:
                assertions=advisories(read_bounded(root/(row["id"]+".advisories.json"),1024*1024),row)
                advisory_status="operator_snapshot_matched"
            except (OSError,ValueError):
                advisory_status="unavailable_or_invalid"
        correlate(parsed["candidates"],findings,assertions)
        return {**parsed,"id":row["id"],"repository":row["url"],"suite":row["suite"],
                "component":row["component"],"keyring_sha256":row["keyring_sha256"],
                "advisory_status":advisory_status,"advisory_sha256":row.get("advisory_sha256")}
    finally:
        subprocess.run(["docker","rm","-f",name],check=False,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

def discover(image,report,plan,root=ROOT):
    policy=root/"approved-binaries.json"
    result={"status":"not_configured","repositories":[],"automatic_selection_count":0,"publication_authorized":False}
    if not policy.exists():
        return result
    try:
        data=read_bounded(policy,64*1024)
        rows=validate(json.loads(data))
        release=vendor.RELEASES[str(report["Metadata"]["OS"]["Name"]).split(".")[0]]
        result["policy_sha256"]=hashlib.sha256(data).hexdigest()
        evidence=(report.get("_appsec") or {}).get("fix_discovery") or {}
        findings=evidence.get("findings") or []
        for row in rows:
            if row["suite"]!=release:
                continue
            try:
                result["repositories"].append(probe(image,row,plan["inventory"],root,findings))
            except StopRequested:
                raise
            except (ValueError,OSError,RuntimeError,subprocess.SubprocessError):
                result["repositories"].append({"id":row["id"],"status":"unavailable","candidates":[]})
        result["status"]="partial" if any(r["status"] in ("unavailable","partial") for r in result["repositories"]) else "completed"
        result["candidate_count"]=sum(len(r["candidates"]) for r in result["repositories"])
    except StopRequested:
        raise
    except (ValueError,OSError,TypeError,KeyError):
        result["status"]="invalid_policy"
    return result
