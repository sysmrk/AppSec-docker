"""Opt-in Ubuntu 24.04 LTS local binary remediation (official main only)."""
import hashlib
import os
import subprocess
from uuid import uuid4
from . import apt_optimization as apt, native_apt, remediation_audit as audit
from . import backport_trial, independent_scan, job_watch
from .workflow_control import StopRequested

MIRROR="ubuntu-official"
ENDPOINTS=("https://archive.ubuntu.com/ubuntu","https://security.ubuntu.com/ubuntu")
PREFIX=r'''
export LC_ALL=C
. /etc/os-release
test "$ID" = ubuntu
test "$VERSION_CODENAME" = noble
test "$(dpkg --print-architecture)" = amd64
test -z "$(dpkg --print-foreign-architectures)"
key=/usr/share/keyrings/ubuntu-archive-keyring.gpg
test -f "$key"
main="$1"; security="$2"; shift 2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
chmod 755 "$work"
mkdir "$work/empty" "$work/lists" "$work/cache"
printf 'deb [signed-by=%s] %s noble main\ndeb [signed-by=%s] %s noble-updates main\ndeb [signed-by=%s] %s noble-security main\n' "$key" "$main" "$key" "$main" "$key" "$security" > "$work/sources.list"
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
'''
PLAN=PREFIX+'apt-get -s --no-remove dist-upgrade\n'
DOWNLOAD=PREFIX+': > "$work/expected"'+backport_trial.archive_script("trixie").split(': > "$work/expected"',1)[1]

def enabled():
    return os.getenv("APPSEC_V4_UBUNTU_TRIAL","false").lower()=="true"

def supports(report):
    info=(report.get("Metadata") or {}).get("OS") or {}
    return info.get("Family")=="ubuntu" and ".".join(str(info.get("Name","")).split(".")[:2])=="24.04"

def plan(image,report):
    if not supports(report) or not audit.verified({"status":"success","raw_report":report}) or report["_appsec"]["image_id"]!=image:
        raise ValueError("Verified Ubuntu 24.04 scan required")
    base=apt.inspect(image)
    if base["Config"].get("User") not in ("","root","0","0:0",None):
        raise ValueError("Only root-default Ubuntu images supported")
    rows=apt.inventory(image)
    name="appsec-ubuntu-probe-"+uuid4().hex
    try:
        output=apt.run(["docker","run","--rm","--pull=never","--name",name,"--user","0:0",
                 "--security-opt","no-new-privileges:true","--pids-limit","128","--memory","1g",
                 "--entrypoint","/bin/sh",image,"-ec",PLAN,"lab",*ENDPOINTS],300)
    finally:
        subprocess.run(["docker","rm","-f",name],check=False,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    updates=native_apt.changes(output,rows)
    for n,v in updates.items():
        apt.container(image,'dpkg --compare-versions "$1" lt "$2"',[v["before"],v["after"]])
        selection=apt.container(image,'dpkg --get-selections "$1"',[n])
        if selection.split()[-1]!="install":
            raise ValueError("Ubuntu package not eligible for upgrade")
    result={"schema":native_apt.SCHEMA,"backend":"native_ubuntu","release":"24.04","image_id":image,
            "mirror":MIRROR,"mirror_priority":[MIRROR],"updates":updates,"inventory":rows,
            "report_sha256":hashlib.sha256(audit.input_bytes(report)).hexdigest(),"publication_authorized":False}
    result["plan_sha256"]=apt.plan_digest(result)
    return result

def attempt(image,report):
    if not enabled() or not independent_scan.enabled():
        return None,{"status":"blocked","backend":"native_ubuntu","message":"Ubuntu trial and independent scan must be enabled","publication_authorized":False}
    candidate=None
    accepted=False
    try:
        job_watch.emit("ubuntu_plan")
        data=plan(image,report)
        if not data["updates"]:
            return None,{**data,"status":"no_updates"}
        job_watch.emit("ubuntu_build")
        candidate=native_apt._build_exact(data,generic=True,
            downloader=lambda image,updates,dest:native_apt.download(image,MIRROR,updates,dest,script=DOWNLOAD,endpoints=ENDPOINTS))
        from .optimization import offline_compare
        reports,hashes,scanner=offline_compare([image,candidate["candidate_image_id"]],report["_appsec"]["scanner_image"])
        a,_,_=independent_scan.scan(image,reports[0]["raw_report"])
        b,_,_=independent_scan.scan(candidate["candidate_image_id"],reports[1]["raw_report"])
        result=backport_trial.gate(reports,a,b)
        result.update(trivy_db_files_sha256=hashes,trivy_image_id=scanner,independent_db_files_sha256=a.get("db_files_sha256"))
        data.update(status=result["status"],validation=result)
        job_watch.checkpoint()
        if result["status"]=="selected_local_candidate":
            accepted=True
            return candidate,data
        return None,data
    except StopRequested:
        raise
    except (ValueError,OSError,RuntimeError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        from .errors import safe_message
        return None,{"status":"blocked","backend":"native_ubuntu","message":safe_message(exc,"patch_build"),"publication_authorized":False}
    finally:
        if candidate and not accepted:
            backport_trial.cleanup(candidate)
