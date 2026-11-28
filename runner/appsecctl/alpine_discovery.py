"""Read-only APK candidate transaction preview for trusted local Alpine images."""
import re
import subprocess
from uuid import uuid4
from . import apt_optimization as apt
from .workflow_control import StopRequested

RELEASE = re.compile(r"3\.[0-9]{1,2}")
UPGRADE = re.compile(r"\(\s*\d+/\d+\) Upgrading ([A-Za-z0-9][A-Za-z0-9+_.-]*) \(([A-Za-z0-9+_.~-]+) -> ([A-Za-z0-9+_.~-]+)\)")
PROBE = r'''
export LC_ALL=C
. /etc/os-release
test "$ID" = alpine
test "$(cut -d. -f1,2 /etc/alpine-release)" = "$1"
test "$(apk --print-arch)" = x86_64
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/cache"
printf 'https://dl-cdn.alpinelinux.org/alpine/v%s/main\nhttps://dl-cdn.alpinelinux.org/alpine/v%s/community\n' "$1" "$1" > "$work/repositories"
apk --repositories-file "$work/repositories" --cache-dir "$work/cache" update >&2
apk --repositories-file "$work/repositories" --cache-dir "$work/cache" upgrade --simulate
echo '@@COMPLETE'
'''

def parse(output):
    lines=output.splitlines()
    if not lines or lines[-1]!="@@COMPLETE":
        raise ValueError("Incomplete APK simulation")
    rows=[]
    blockers=[]
    seen=set()
    for line in lines[:-1]:
        line=line.strip()
        match=UPGRADE.fullmatch(line)
        if match:
            name,old,new=match.groups()
            if name in seen or old==new or len(rows)>=2000:
                raise ValueError("Ambiguous APK transaction")
            seen.add(name)
            rows.append({"package":name,"before":old,"candidate":new,"decision":"REVIEW_REQUIRED"})
        elif re.match(r"^\(\s*\d+/\d+\)",line):
            blockers.append("non_upgrade_or_unknown_action")
        elif line.startswith(("ERROR:","WARNING:")):
            blockers.append("apk_diagnostic")
        elif line and not line.startswith(("OK:","Executing ","(simulation)")):
            blockers.append("unrecognized_output")
    return {"status":"review_required" if blockers else "completed","candidates":rows,
            "candidate_count":len(rows),"blockers":sorted(set(blockers)),
            "automatic_selection_count":0,"publication_authorized":False}

def discover(report):
    info=(report.get("Metadata") or {}).get("OS") or {}
    release=".".join(str(info.get("Name","")).split(".")[:2])
    result={"status":"unsupported","message":"APK discovery requires an Alpine 3.x trusted local linux/amd64 image.",
            "automatic_selection_count":0,"publication_authorized":False}
    if info.get("Family")!="alpine" or not RELEASE.fullmatch(release):
        return result
    name="appsec-apk-probe-"+uuid4().hex
    try:
        evidence=report.get("_appsec") or {}
        if evidence.get("verified") is not True:
            raise ValueError("Verified original scan required")
        image=evidence["image_id"]
        apt.inspect(image)
        output=apt.run(["docker","run","--rm","--name",name,"--pull=never","--user","0:0",
             "--cap-drop","ALL","--security-opt","no-new-privileges:true","--pids-limit","128","--memory","1g",
             "--entrypoint","/bin/sh",image,"-ec",PROBE,"probe",release],180)
        result=parse(output)
        result.update(release=release,repository="official Alpine main/community",message="Read-only APK simulation using image-provided Alpine keys; no archive verification, lifecycle check, security proof or installation.")
        return result
    except StopRequested:
        raise
    except (ValueError,OSError,RuntimeError,KeyError,subprocess.SubprocessError):
        return {"status":"unavailable","message":"APK repository simulation could not be verified.","automatic_selection_count":0,"publication_authorized":False}
    finally:
        subprocess.run(["docker","rm","-f",name],check=False,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
