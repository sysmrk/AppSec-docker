"""P0: local, explicit Debian package availability and nginx debloat lab.

No database writes, no push, no automatic modification of a workflow.
Plan and build are separate; the approved closure is checked before AND after.
Run only with trusted test images on a dedicated Docker daemon.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import time
import subprocess
import sys
import tempfile
from uuid import uuid4

from . import remediation_audit as audit

SCHEMA = "appsec.apt-debloat-plan/v1"
ID = re.compile(r"sha256:[a-f0-9]{64}")
PKG = re.compile(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?")
OPTIONAL = ("nginx-module-image-filter", "nginx-module-xslt", "nginx-module-geoip")
FORMAT = r'${binary:Package}\t${Version}\t${db:Status-Status}\t${Essential}\t${Protected}\t${Priority}\n'
# Explicit operator-selected endpoint pairs, not arbitrary URLs or automatic fallback.
MIRRORS = {
    "tuna": ("https://mirrors.tuna.tsinghua.edu.cn/debian",
             "https://mirrors.tuna.tsinghua.edu.cn/debian-security"),
    "debian": ("https://deb.debian.org/debian", "https://deb.debian.org/debian-security"),
}


def run(args, timeout=180, *, capture=True):
    # Host CLI has no DB dependency. Worker can attach bounded live telemetry.
    watch=sys.modules.get("appsecctl.job_watch")
    if watch is not None and watch.CURRENT.get() is not None:
        watch.checkpoint()
        result=watch.capture_output(args,timeout=timeout) if capture else watch.capture_stderr(args,timeout=timeout)
        watch.checkpoint()
        return result
    if capture:
        return subprocess.run(args,check=True,text=True,timeout=timeout,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout
    # Host-side lab: stream BuildKit stderr while retaining a bounded tail.
    # Previously stderr was inherited, so CalledProcessError had no diagnostic.
    deadline=time.monotonic()+timeout
    tail=b""
    with subprocess.Popen(args,stdout=sys.stderr,stderr=subprocess.PIPE) as proc:
        try:
            with selectors.DefaultSelector() as sel:
                sel.register(proc.stderr,selectors.EVENT_READ)
                while sel.get_map():
                    remaining=deadline-time.monotonic()
                    if remaining<=0:
                        raise subprocess.TimeoutExpired(args,timeout,stderr=tail.decode(errors="replace"))
                    for key,_ in sel.select(min(1,remaining)):
                        block=os.read(key.fd,8192)
                        if not block:
                            sel.unregister(key.fileobj)
                            continue
                        tail=(tail+block)[-65536:]
                        print(block.decode(errors="replace"),end="",file=sys.stderr,flush=True)
            code=proc.wait(timeout=max(0,deadline-time.monotonic()))
            if code:
                raise subprocess.CalledProcessError(code,args,stderr=tail.decode(errors="replace"))
        except BaseException:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            raise


def inspect(image):
    if not ID.fullmatch(image):
        raise ValueError("Use immutable local image config ID (sha256:...)")
    row, = json.loads(run(["docker","image","inspect",image]))
    if row["Id"] != image or row["Os"] != "linux" or row["Architecture"] != "amd64":
        raise ValueError("Only exact local linux/amd64 images are supported")
    if row.get("Config",{}).get("Volumes"):
        raise ValueError("Images declaring volumes are not supported in this lab")
    return row


def container(image, script, args=(), *, network="none", writable=False, timeout=180):
    name = "appsec-apt-lab-" + uuid4().hex
    cmd = ["docker","run","--rm","--name",name,"--pull=never","--network",network,
           "--user","0:0","--cap-drop","ALL","--security-opt","no-new-privileges:true",
           "--pids-limit","128","--memory","1g","--cpus","2"]
    if not writable:
        cmd += ["--read-only"]
    cmd += ["--entrypoint","/bin/sh",image,"-ec",script,"lab",*args]
    try:
        return run(cmd, timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        subprocess.run(["docker","rm","-f",name],check=False,timeout=30,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        raise


def progress(event):
    watch=sys.modules.get("appsecctl.job_watch")
    if watch is not None:
        watch.emit(event)


def inventory(image):
    progress("apt_inventory")
    output = container(image, 'export LC_ALL=C; dpkg-query -W -f="$1"', [FORMAT])
    rows = {}
    for line in output.splitlines():
        name, version, status, essential, protected, priority = line.split("\t")
        if status != "installed":
            continue
        if not PKG.fullmatch(name) or not version or name in rows:
            raise ValueError("Ambiguous dpkg inventory")
        rows[name] = {"version":version,"essential":essential=="yes",
                      "protected":protected=="yes","priority":priority}
    if not rows:
        raise ValueError("Empty package inventory")
    return rows


def resolve(name, rows):
    if name in rows:
        return name
    # Never resolve an explicitly different architecture by package name.
    matches = [p for p in rows if p.split(":")[0] == name.split(":")[0]
               and (":" not in name or (":" not in p and name.endswith(":amd64")))]
    if len(matches) != 1:
        raise ValueError("Ambiguous package in APT simulation: " + name)
    return matches[0]


def parse_simulation(output, rows):
    removed = set()
    for line in output.splitlines():
        if line.startswith(("Inst ","Conf ")):
            raise ValueError("Removal would also install/configure packages")
        if line.startswith(("Purg ","Remv ")):
            removed.add(resolve(line.split()[1],rows))
    summary = re.findall(r"^(\d+) upgraded, (\d+) newly installed, (\d+) to remove and (\d+) not upgraded\.$", output, re.M)
    if len(summary)!=1 or tuple(map(int,summary[0][:3])) != (0,0,len(removed)) or not removed:
        raise ValueError("Unrecognized or inconsistent APT simulation")
    return sorted(removed)


def plan_digest(plan):
    return hashlib.sha256(audit.input_bytes({k:v for k,v in plan.items() if k!="plan_sha256"})).hexdigest()


def plan_removal(image, roots, report):
    inspect(image)
    if not roots or len(set(roots))!=len(roots) or not set(roots)<=set(OPTIONAL):
        raise ValueError("Only explicitly selected nginx optional modules are supported")
    if not audit.verified({"status":"success","raw_report":report}) or report["_appsec"]["image_id"]!=image:
        raise ValueError("A verified raw scan of the exact base image is required")
    os_info = report.get("Metadata", {}).get("OS") or {}
    if os_info.get("Family") != "debian" or str(os_info.get("Name","")).split(".")[0] not in ("12","13"):
        raise ValueError("Only Debian 12/13 nginx images are supported")
    rows = inventory(image)
    if "nginx" not in rows or not set(roots)<=rows.keys():
        raise ValueError("Required nginx packages not present")
    manual_raw = container(image, "export LC_ALL=C; apt-mark showmanual")
    manual = {resolve(p,rows) for p in manual_raw.splitlines() if p and
              (p in rows or any(n.split(':')[0]==p.split(':')[0] for n in rows))}
    progress("apt_simulate")
    output = container(image, 'export LC_ALL=C; apt-get -s --auto-remove purge -- "$@"', roots)
    removed = parse_simulation(output,rows)
    if not set(roots)<=set(removed):
        raise ValueError("Requested modules missing from removal closure")
    for p in removed:
        item=rows[p]
        bare=p.split(":")[0]
        if (item["essential"] or item["protected"] or item["priority"] in ("required","important")
                or (p in manual and p not in roots)
                or (bare.startswith("nginx") and p not in roots)
                or bare in {"libc6","libc-bin","libssl3t64","openssl","dpkg","apt","bash","dash","ca-certificates","curl"}):
            raise ValueError("Protected or non-approved manual package in removal closure: "+p)
    findings = Counter()
    for target in report["Results"]:
        if target["Class"] != "os-pkgs":
            continue
        for v in target.get("Vulnerabilities") or []:
            matches=[p for p in removed if p.split(":")[0]==v["PkgName"].split(":")[0]]
            if len(matches)==1 and rows[matches[0]]["version"]==v["InstalledVersion"]:
                findings[str(v.get("Severity") or "UNKNOWN").upper()]+=1
    plan={"schema":SCHEMA,"image_id":image,"roots":sorted(roots),"remove":removed,
          "inventory":rows,"report_sha256":hashlib.sha256(audit.input_bytes(report)).hexdigest(),
          "estimated_findings_by_severity":dict(findings),
          "estimated_findings":sum(findings.values()),"approval_required":True,
          "publication_authorized":False}
    plan["plan_sha256"]=plan_digest(plan)
    return plan


def dockerfile(roots, closure):
    # Names are strictly validated and the approved plan is regenerated.
    # Exact closure comparison inside the build; no remote package downloads.
    for p in [*roots,*closure]:
        if not PKG.fullmatch(p):
            raise ValueError("Invalid package token")
    root_args=" ".join(roots)
    # APT often prints unqualified names; on this initial amd64 lab the
    # inventory has been checked for ambiguity. Compare normalized names.
    names=[p.split(":")[0] for p in closure]
    if len(set(names))!=len(names):
        raise ValueError("Multiarch removal closure unsupported")
    expected=" ".join(sorted(names))
    return (
        "ARG BASE_IMAGE=appsec-lab/base:invalid\nFROM ${BASE_IMAGE}\n"
        "RUN set -eu; export LC_ALL=C; "
        + "apt-get -s --auto-remove purge -- "+root_args+" > /tmp/appsec-plan; "
        + "actual=$(awk '/^(Purg|Remv) / {sub(/:[^ ]+$/, \"\", $2); print $2}' /tmp/appsec-plan | sort -u | paste -sd ' '); "
        + "test \"$actual\" = '"+expected+"'; "
        + "if grep -Eq '^(Inst|Conf) ' /tmp/appsec-plan; then exit 42; fi; "
        + "apt-get -y --no-download --auto-remove purge -- "+root_args+"; "
        + "test -z \"$(dpkg --audit)\"; nginx -t; rm -f /tmp/appsec-plan\n"
    )


def build(plan, report, approved):
    if plan.get("schema")!=SCHEMA or plan.get("plan_sha256")!=approved or plan_digest(plan)!=approved:
        raise ValueError("Plan digest mismatch")
    image=plan["image_id"]
    current=plan_removal(image,plan["roots"],report)
    if current != plan:
        raise ValueError("Stale plan: recompute and approve again")
    base=inspect(image)
    if base.get("Config",{}).get("User") not in ("","root","0","0:0",None):
        raise ValueError("Only root-default build images supported")
    uid=uuid4().hex
    tag="appsec-lab/debloat-base:"+uid
    output="appsec-lab/debloated:"+uid
    run(["docker","tag",image,tag])
    try:
        with tempfile.TemporaryDirectory(prefix="appsec-debloat-") as tmp:
            Path(tmp,"Dockerfile").write_text(dockerfile(plan["roots"],plan["remove"]))
            run(["docker","buildx","build","--builder","default","--progress","plain","--load","--pull=false",
                 "--network=none","--no-cache","--build-arg","BASE_IMAGE="+tag,
                 "-t",output,tmp],1800,capture=False)
        candidate_id=run(["docker","image","inspect","--format","{{.Id}}",output]).strip()
        candidate=inspect(candidate_id)
        if candidate_id==image or candidate["RootFS"]["Layers"][:len(base["RootFS"]["Layers"])]!=base["RootFS"]["Layers"]:
            raise ValueError("Candidate does not extend approved base layers")
        keys=("Entrypoint","Cmd","User","Env","WorkingDir","ExposedPorts","Healthcheck","Volumes","StopSignal","Labels")
        if any(base["Config"].get(k)!=candidate["Config"].get(k) for k in keys):
            raise ValueError("Runtime config changed")
        expected={k:v for k,v in current["inventory"].items() if k not in current["remove"]}
        if inventory(candidate_id)!=expected:
            raise ValueError("Actual package changes differ from approved closure")
        return {"schema":"appsec.apt-debloat-candidate/v1","status":"candidate_prepared",
                "base_image_id":image,"candidate":output,"candidate_image_id":candidate_id,
                "approved_plan_sha256":approved,"removed_packages":current["remove"],
                "rescan_required":True,"functional_test_passed":False,"publication_authorized":False,
                "historical_layers_removed":False}
    except BaseException:
        # Remove only the unique failed candidate alias, never the source.
        subprocess.run(["docker","image","rm",output],check=False,timeout=30,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        raise
    finally:
        # Only our unique temporary reference, never the input image.
        subprocess.run(["docker","image","rm",tag],check=False,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


def availability(image, mirror):
    inspect(image)
    main, security=MIRRORS[mirror]
    # Disable all existing source entries for this disposable probe; preserve
    # signature checks and explicitly select the same release's security suite.
    script=r'''
export LC_ALL=C
. /etc/os-release
test "$ID" = debian
case "$VERSION_CODENAME" in bookworm|trixie) ;; *) exit 21;; esac
test -f /usr/share/keyrings/debian-archive-keyring.pgp || test -f /usr/share/keyrings/debian-archive-keyring.gpg
key=/usr/share/keyrings/debian-archive-keyring.pgp
test -f "$key" || key=/usr/share/keyrings/debian-archive-keyring.gpg
mkdir -p /tmp/appsec-apt-empty
printf 'deb [signed-by=%s] %s %s main\ndeb [signed-by=%s] %s %s-updates main\ndeb [signed-by=%s] %s %s-security main\n' "$key" "$1" "$VERSION_CODENAME" "$key" "$1" "$VERSION_CODENAME" "$key" "$2" "$VERSION_CODENAME" > /tmp/appsec-apt.list
rm -rf /var/lib/apt/lists/*
apt-get -o Dir::Etc::sourcelist=/tmp/appsec-apt.list -o Dir::Etc::sourceparts=/tmp/appsec-apt-empty -o Acquire::https::AllowRedirect=false -o Acquire::http::AllowRedirect=false -o APT::Get::AllowUnauthenticated=false -o APT::Update::Error-Mode=any -o Acquire::Retries=1 -o Acquire::https::Timeout=30 -o Acquire::Check-Valid-Until=true -o Acquire::AllowInsecureRepositories=false -o Acquire::https::Verify-Peer=true -o Acquire::https::Verify-Host=true update >&2
apt-get -o Dir::Etc::sourcelist=/tmp/appsec-apt.list -o Dir::Etc::sourceparts=/tmp/appsec-apt-empty -s dist-upgrade
'''
    # apt may need to drop privileges to _apt. Use ordinary Docker default
    # capabilities only for this explicit networked metadata probe.
    progress("apt_probe")
    name="appsec-apt-probe-"+uuid4().hex
    try:
        out=run(["docker","run","--rm","--pull=never","--name",name,"--user","0:0",
                 "--security-opt","no-new-privileges:true","--pids-limit","128",
                 "--memory","1g","--entrypoint","/bin/sh",image,"-ec",script,"lab",main,security],300)
    except (subprocess.TimeoutExpired,KeyboardInterrupt):
        subprocess.run(["docker","rm","-f",name],check=False,timeout=30,stdout=subprocess.DEVNULL)
        raise
    summary = re.findall(r"^(\d+) upgraded, (\d+) newly installed, (\d+) to remove and (\d+) not upgraded\.$",out,re.M)
    if len(summary) != 1:
        raise ValueError("APT simulation summary missing")
    return {"schema":"appsec.apt-availability/v1","status":"repository_checked",
            "image_id":image,"mirror":mirror,"simulation":out,
            "counts":dict(zip(("upgraded","newly_installed","removed","not_upgraded"),map(int,summary[0]))),
            "installed_or_upgraded":False,"publication_authorized":False}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest="command",required=True)
    probe=sub.add_parser("availability")
    probe.add_argument("--image",required=True)
    probe.add_argument("--mirror",choices=sorted(MIRRORS),required=True)
    p=sub.add_parser("plan")
    p.add_argument("--image",required=True)
    p.add_argument("--report",type=Path,required=True)
    p.add_argument("--remove",action="append",choices=OPTIONAL,required=True)
    b=sub.add_parser("build")
    b.add_argument("--plan",type=Path,required=True)
    b.add_argument("--report",type=Path,required=True)
    b.add_argument("--approve-sha256",required=True)
    for s in (probe,p,b):
        s.add_argument("--confirm-isolated-lab",action="store_true",required=True)
    args=parser.parse_args(argv)
    try:
        if args.command=="availability":
            result=availability(args.image,args.mirror)
        elif args.command=="plan":
            result=plan_removal(args.image,args.remove,json.loads(args.report.read_text()))
        else:
            result=build(json.loads(args.plan.read_text()),json.loads(args.report.read_text()),args.approve_sha256)
    except (OSError,ValueError,RuntimeError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        print("APT_LAB_FAILED: "+str(exc)[:500],file=sys.stderr)
        return 1
    print(json.dumps(result,indent=2,ensure_ascii=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
