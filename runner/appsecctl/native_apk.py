"""Opt-in Alpine 3.22 / APK v2 local-only signed native transaction."""
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from uuid import uuid4

from . import alpine_discovery as discovery, approved_binaries as ab
from . import apt_optimization as apt, backport_trial, independent_scan, job_watch
from . import native_apt, remediation_audit as audit
from .workflow_control import StopRequested

RELEASE="3.22"
END=date(2027,5,1)
ROOT=Path("/vendor-snapshots")
NAME=re.compile(r"[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}")
VERSION=re.compile(r"[0-9][A-Za-z0-9+_.~-]{0,191}")
KEY=re.compile(r"[A-Za-z0-9@._+-]{1,160}\.rsa\.pub")
MAX_BYTES=512*1024*1024

def enabled():
    return os.getenv("APPSEC_V4_APK_TRIAL","false").lower()=="true"

def supports(report):
    info=(report.get("Metadata") or {}).get("OS") or {}
    return info.get("Family")=="alpine" and ".".join(str(info.get("Name","")).split(".")[:2])==RELEASE and date.today()<END

def digest(path):
    h=hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(1024*1024),b""):
            h.update(block)
    return h.hexdigest()

def policy(root=ROOT):
    data=ab.read_bounded(root/"alpine-keys.json",65536)
    doc=json.loads(data)
    if not isinstance(doc,dict) or set(doc)!={"schema","release","keys"} or doc["schema"]!="appsec.alpine-keys/v1" or doc["release"]!=RELEASE:
        raise ValueError("Invalid Alpine trust policy")
    keys=doc["keys"]
    if not isinstance(keys,dict) or not 1<=len(keys)<=32:
        raise ValueError("Alpine signing keys required")
    content={}
    for name,sha in keys.items():
        if not KEY.fullmatch(name) or not isinstance(sha,str) or not ab.DIGEST.fullmatch(sha):
            raise ValueError("Invalid Alpine key identity")
        raw=ab.read_bounded(root/"alpine-keys"/name,65536)
        if hashlib.sha256(raw).hexdigest()!=sha:
            raise ValueError("Alpine key digest mismatch")
        content[name]=raw
    return hashlib.sha256(data).hexdigest(),content

def inventory(image):
    output=apt.container(image,r'''
export LC_ALL=C
test "$(cut -d. -f1,2 /etc/alpine-release)" = "$1"
test "$(apk --print-arch)" = x86_64
apk --version | grep -Eq '(^| )2\.[0-9]'
awk -F: '/^P:/{p=substr($0,3)} /^V:/{v=substr($0,3)} /^A:/{a=substr($0,3)}
  /^$/{if(p!=""){print p "\t" v "\t" a};p=v=a=""} END{if(p!=""){print p "\t" v "\t" a}}' /lib/apk/db/installed
printf '@@WORLD\t'; sha256sum /etc/apk/world | cut -d' ' -f1
printf '@@REPOSITORIES\t'; sha256sum /etc/apk/repositories | cut -d' ' -f1
''',[RELEASE])
    return parse_inventory(output)

def parse_inventory(output):
    rows={}
    state={}
    for line in output.splitlines():
        parts=line.split("\t")
        if len(parts)==2 and parts[0] in ("@@WORLD","@@REPOSITORIES"):
            if parts[0] in state or not ab.DIGEST.fullmatch(parts[1]):
                raise ValueError("Ambiguous APK config evidence")
            state[parts[0]]=parts[1]
        elif len(parts)==3:
            name,version,arch=parts
            if name in rows or not NAME.fullmatch(name) or not VERSION.fullmatch(version) or arch not in ("x86_64","noarch"):
                raise ValueError("Invalid APK package inventory")
            rows[name]={"version":version,"architecture":arch}
        else:
            raise ValueError("Unexpected APK inventory")
    if not rows or len(rows)>2000 or len(state)!=2:
        raise ValueError("Incomplete APK inventory")
    return {"packages":rows,"world_sha256":state["@@WORLD"],"repositories_sha256":state["@@REPOSITORIES"]}

def changes(output,rows):
    parsed=discovery.parse(output)
    if parsed["status"]!="completed":
        raise ValueError("APK simulation contains unsupported actions")
    result={}
    for c in parsed["candidates"]:
        n=c["package"]; old=c["before"]; new=c["candidate"]
        if n not in rows or rows[n]["version"]!=old or not VERSION.fullmatch(new):
            raise ValueError("APK plan inventory mismatch")
        result[n]={"before":old,"after":new}
    return result

# The networked disposable container stages one signed index and exact archives.
# Trust is supplied by the operator; do not use the image's key store.
STAGE=r'''
export LC_ALL=C
unset SSL_NO_VERIFY_HOSTNAME
. /etc/os-release
test "$ID" = alpine
test "$(cut -d. -f1,2 /etc/alpine-release)" = 3.22
test "$(apk --print-arch)" = x86_64
apk --version | grep -Eq '(^| )2\.[0-9]'
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
test ! -e /tmp/appsec-apk-output
mkdir -p "$work/cache" /tmp/appsec-apk-output/x86_64
printf '%s\n' 'https://dl-cdn.alpinelinux.org/alpine/v3.22/main' > "$work/repositories"
apk_safe() {
    apk --keys-dir /tmp/appsec-apk-keys --repositories-file "$work/repositories" --cache-dir "$work/cache" --no-progress "$@"
}
apk_safe update >&2
apk_safe upgrade --simulate --no-self-upgrade > "$work/plan"
cat "$work/plan"
echo '@@COMPLETE'
# Only fetch recognizable upgrades, never resolve extra packages.
awk '/^\([0-9]+\/[0-9]+\) / {
  if ($2!="Upgrading" || NF!=6 || $5!="->") exit 1;
  v=$6;sub(/\)$/,"",v);print $3 "=" v
}' "$work/plan" > "$work/pins"
count=$(wc -l < "$work/pins")
test "$count" -le 128
if test "$count" -eq 0; then exit 0; fi
for pin in $(cat "$work/pins"); do
    name=${pin%%=*}; ver=${pin#*=}
    old=$(awk -v n="$name" '/^P:/{p=substr($0,3)} /^V:/ && p==n {print substr($0,3)}' /lib/apk/db/installed)
    test -n "$old"
    test "$(apk version -t "$old" "$ver")" = '<'
    apk_safe fetch --output /tmp/appsec-apk-output/x86_64 "$pin" >&2
done
set -- "$work/cache"/APKINDEX.*.tar.gz
test "$#" -eq 1
test -f "$1"
cp "$1" /tmp/appsec-apk-output/x86_64/APKINDEX.tar.gz
apk --keys-dir /tmp/appsec-apk-keys verify /tmp/appsec-apk-output/x86_64/*.apk >&2
test "$(du -sk /tmp/appsec-apk-output | cut -f1)" -le 524288
'''

def stage(image,keys,dest,rows):
    name="appsec-apk-stage-"+uuid4().hex
    try:
        with tempfile.TemporaryDirectory(prefix="appsec-apk-keys-") as tmp:
            keydir=Path(tmp)/"keys";keydir.mkdir()
            for k,data in keys.items():
                (keydir/k).write_bytes(data)
            apt.run(["docker","create","--name",name,"--pull=never","--user","0:0",
                     "--security-opt","no-new-privileges:true","--pids-limit","128","--memory","1g",
                     "--entrypoint","/bin/sh",image,"-ec",STAGE],60)
            apt.run(["docker","cp",str(keydir),name+":/tmp/appsec-apk-keys"],30)
            output=apt.run(["docker","start","-a",name],420)
            if apt.run(["docker","inspect","--format","{{.State.ExitCode}}",name]).strip()!="0":
                raise ValueError("APK staging failed")
            updates=changes(output,rows)
            if updates:
                apt.run(["docker","cp",name+":/tmp/appsec-apk-output/.",str(dest)],180)
            return updates
    finally:
        subprocess.run(["docker","rm","-f",name],check=False,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

def verify_stage(dest,updates):
    arch=dest/"x86_64"
    if arch.is_symlink() or not arch.is_dir() or set(p.name for p in dest.iterdir())!={"x86_64"}:
        raise ValueError("Unexpected APK stage layout")
    names={"APKINDEX.tar.gz",*(n+"-"+v["after"]+".apk" for n,v in updates.items())}
    paths=list(arch.iterdir())
    if {p.name for p in paths}!=names or any(p.is_symlink() or not p.is_file() or not 0<p.stat().st_size<=MAX_BYTES for p in paths) or sum(p.stat().st_size for p in paths)>MAX_BYTES:
        raise ValueError("APK archive set or size mismatch")
    return {p.name:digest(p) for p in paths}

def validate_after(before,after,updates):
    expected={n:{**v,"version":updates.get(n,{}).get("after",v["version"])} for n,v in before["packages"].items()}
    if after["packages"]!=expected or any(before[k]!=after[k] for k in ("world_sha256","repositories_sha256")):
        raise ValueError("APK inventory or configuration differs from exact plan")

def build(image,report,root=ROOT):
    if not supports(report) or not audit.verified({"status":"success","raw_report":report}) or report["_appsec"]["image_id"]!=image:
        raise ValueError("Verified supported Alpine report required")
    base=apt.inspect(image)
    if base["Config"].get("User") not in ("","root","0","0:0",None):
        raise ValueError("Root-default Alpine images only")
    trust,keys=policy(root)
    before=inventory(image)
    uid=uuid4().hex
    tag="appsec-lab/apk-base:"+uid
    output="appsec-lab/apk-upgraded:"+uid
    accepted=False
    try:
        with tempfile.TemporaryDirectory(prefix="appsec-native-apk-") as tmp:
            ctx=Path(tmp)
            repo=ctx/"repository";repo.mkdir()
            job_watch.emit("apk_plan")
            updates=stage(image,keys,repo,before["packages"])
            if not updates:
                return None,{"status":"no_updates","backend":"native_apk","release":RELEASE,"publication_authorized":False}
            hashes=verify_stage(repo,updates)
            if policy(root)[0]!=trust:
                raise ValueError("Alpine trust policy changed")
            keydir=ctx/"keys";keydir.mkdir()
            for k,data in keys.items():
                (keydir/k).write_bytes(data)
            (ctx/"checksums").write_text("".join(sha+"  /tmp/appsec-repository/x86_64/"+n+"\n" for n,sha in sorted(hashes.items())))
            (ctx/"Dockerfile").write_text(
                "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n"
                "RUN --mount=type=bind,source=repository,target=/tmp/appsec-repository,readonly "
                "--mount=type=bind,source=keys,target=/tmp/appsec-keys,readonly "
                "--mount=type=bind,source=checksums,target=/tmp/appsec-checksums,readonly "
                "set -eu; sha256sum -c /tmp/appsec-checksums; "
                "work=$(mktemp -d); trap 'rm -rf \"$work\"' EXIT; mkdir \"$work/cache\"; "
                "printf '%s\\n' /tmp/appsec-repository > \"$work/repositories\"; "
                "apk --keys-dir /tmp/appsec-keys verify /tmp/appsec-repository/x86_64/*.apk; "
                "apk --keys-dir /tmp/appsec-keys --repositories-file \"$work/repositories\" --cache-dir \"$work/cache\" --no-network upgrade --no-self-upgrade\n")
            plan={"backend":"native_apk","release":RELEASE,"image_id":image,"updates":updates,"inventory":before,
                  "key_policy_sha256":trust,"signed_index_sha256":hashes["APKINDEX.tar.gz"],"archives_sha256":hashes,
                  "publication_authorized":False}
            plan["plan_sha256"]=apt.plan_digest(plan)
            apt.run(["docker","tag",image,tag])
            job_watch.emit("apk_build")
            apt.run(["docker","buildx","build","--builder","default","--progress","plain","--load","--pull=false","--network=none","--no-cache","--build-arg","BASE_IMAGE="+tag,"-t",output,tmp],1800,capture=False)
        iid=apt.run(["docker","image","inspect","--format","{{.Id}}",output]).strip()
        after=apt.inspect(iid)
        layers=base["RootFS"]["Layers"]
        if iid==image or after["RootFS"]["Layers"][:len(layers)]!=layers or any(base["Config"].get(k)!=after["Config"].get(k) for k in native_apt.CONFIG_KEYS):
            raise ValueError("APK candidate lineage or runtime configuration changed")
        validate_after(before,inventory(iid),updates)
        if inventory(image)!=before or policy(root)[0]!=trust:
            raise ValueError("Original image or trust policy changed")
        candidate={"schema":"appsec.native-apk-candidate/v1","candidate":output,"candidate_image_id":iid,
                   "base_image_id":image,"updated_packages":updates,"approved_plan_sha256":plan["plan_sha256"],
                   "downloaded_archives_sha256":hashes,"functional_test_passed":False,"publication_authorized":False}
        accepted=True
        return candidate,{**plan,"status":"candidate_prepared"}
    finally:
        subprocess.run(["docker","image","rm",tag],check=False,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if not accepted:
            subprocess.run(["docker","image","rm",output],check=False,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

def attempt(image,report):
    if not enabled() or not independent_scan.enabled():
        return None,{"status":"blocked","backend":"native_apk","message":"APK trial and independent scan must be enabled","publication_authorized":False}
    candidate=None
    accepted=False
    try:
        candidate,plan=build(image,report)
        if not candidate:
            return None,plan
        from .optimization import offline_compare
        reports,hashes,scanner=offline_compare([image,candidate["candidate_image_id"]],report["_appsec"]["scanner_image"])
        a,_,_=independent_scan.scan(image,reports[0]["raw_report"])
        b,_,_=independent_scan.scan(candidate["candidate_image_id"],reports[1]["raw_report"])
        result=backport_trial.gate(reports,a,b)
        result.update(trivy_db_files_sha256=hashes,trivy_image_id=scanner,independent_db_files_sha256=a.get("db_files_sha256"))
        plan["validation"]=result
        plan["status"]=result["status"]
        job_watch.checkpoint()
        if result["status"]=="selected_local_candidate":
            accepted=True
            return candidate,plan
        return None,plan
    except StopRequested:
        raise
    except (OSError,ValueError,RuntimeError,TypeError,KeyError,subprocess.SubprocessError) as exc:
        from .errors import safe_message
        return None,{"status":"blocked","backend":"native_apk","message":safe_message(exc,"patch_build"),"publication_authorized":False}
    finally:
        if candidate and not accepted:
            backport_trial.cleanup(candidate)
