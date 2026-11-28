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
        if not isinstance(row, dict) or set(row) != {"id", "url", "suite", "component", "keyring_sha256", "packages"}:
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
for name do
  old=$(dpkg-query -W -f='${Version}' "$name")
  src=$(dpkg-query -W -f='${source:Package}' "$name")
  best=
  for ver in $(apt-cache madison "$name" | awk -F '|' 'NF==3 {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}'); do
    if dpkg --compare-versions "$ver" gt "$old" &&
       { test -z "$best" || dpkg --compare-versions "$ver" gt "$best"; }; then best=$ver; fi
  done
  test -n "$best" || continue
  printf '@@PACKAGE\t%s\t%s\t%s\t%s\n' "$name" "$old" "$src" "$best"
  apt-cache show "$name=$best" | awk '/^(Package|Version|Architecture|Source|SHA256|Size|Filename): /{print} /^$/{print ""}'
  echo '@@ENDPACKAGE'
done
echo '@@COMPLETE'
'''

def parse(output, inventory, allowed):
    lines=output.splitlines()
    if not lines or lines[-1]!="@@COMPLETE":
        raise ValueError("Incomplete approved repository probe")
    i=0
    seen=set()
    result=[]
    while i<len(lines)-1:
        parts=lines[i].split("\t")
        if len(parts)!=5 or parts[0]!="@@PACKAGE":
            raise ValueError("Unexpected candidate marker")
        _,name,old,src,new=parts
        if (name in seen or name not in allowed or name not in inventory or inventory[name]["version"]!=old
            or not NAME.fullmatch(src) or not native_apt.VERSION.fullmatch(new) or not native_apt.VERSION.fullmatch(old)
            or vendor.ge(old,new)):
            raise ValueError("Candidate identity mismatch")
        end=lines.index("@@ENDPACKAGE",i+1)
        candidate={"package":name,"before":old,"candidate":new,"installed_source":src,
                   "decision":"REVIEW_REQUIRED","security_status":"unverified"}
        try:
            candidate.update(binary.metadata("\n".join(lines[i+1:end]),name,new))
            candidate["status"]="signed_binary_found" if candidate["source_package"]==src else "source_identity_changed"
        except ValueError:
            candidate["status"]="binary_identity_unverified"
        result.append(candidate)
        seen.add(name)
        i=end+1
    return result

def probe(image,row,inventory,root):
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
        return {"id":row["id"],"status":"completed","repository":row["url"],"suite":row["suite"],
                "component":row["component"],"keyring_sha256":row["keyring_sha256"],
                "candidates":parse(output,inventory,names)}
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
        for row in rows:
            if row["suite"]!=release:
                continue
            try:
                result["repositories"].append(probe(image,row,plan["inventory"],root))
            except StopRequested:
                raise
            except (ValueError,OSError,RuntimeError,subprocess.SubprocessError):
                result["repositories"].append({"id":row["id"],"status":"unavailable","candidates":[]})
        result["status"]="partial" if any(r["status"]=="unavailable" for r in result["repositories"]) else "completed"
        result["candidate_count"]=sum(len(r["candidates"]) for r in result["repositories"])
    except StopRequested:
        raise
    except (ValueError,OSError,TypeError,KeyError):
        result["status"]="invalid_policy"
    return result
