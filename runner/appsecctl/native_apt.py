"""Debian 12/13 native APT upgrade candidate, initial trusted nginx lab only.

Plan exact existing-package upgrades using signed configured sources; refuse
new packages, removals, downgrades and held packages. Download via APT in a
disposable networked container; install local .deb archives in a networkless
build. Never mutate original image, APT config, existing patch or registry.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
from uuid import uuid4

from . import apt_optimization as apt, apt_repository_review as repo, remediation_audit as audit

SCHEMA="appsec.native-apt-plan/v1"
VERSION=re.compile(r"[0-9][A-Za-z0-9.+:~\-]{0,191}")
INST=re.compile(r"^Inst ([a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?) \[([^\]]+)\] \(([^ ]+)(?: .*)?\)$",re.M)
CONFIG_KEYS=("Entrypoint","Cmd","User","Env","WorkingDir","ExposedPorts","Healthcheck","Volumes","StopSignal","Labels")


def changes(simulation, rows):
    summary=re.findall(r"^(\d+) upgraded, (\d+) newly installed, (\d+) to remove and (\d+) not upgraded\.$",simulation,re.M)
    if len(summary)!=1:
        raise ValueError("APT summary unavailable")
    n,added,removed,held=map(int,summary[0])
    if added or removed or held or re.search(r"^(?:Remv|Purg) ",simulation,re.M):
        raise ValueError("Native upgrade would add/remove/hold packages; manual review required")
    result={}
    for line in simulation.splitlines():
        if not line.startswith("Inst "):
            continue
        match=INST.fullmatch(line)
        if not match:
            raise ValueError("Unsupported APT upgrade line")
        name=apt.resolve(match[1],rows)
        old,new=match[2],match[3]
        if name in result or old!=rows[name]["version"] or not VERSION.fullmatch(old) or not VERSION.fullmatch(new) or old==new:
            raise ValueError("Ambiguous upgrade version")
        result[name]={"before":old,"after":new}
    if len(result)!=n:
        raise ValueError("APT upgrade count mismatch")
    return result


def plan(image,report,mirrors):
    apt.inspect(image)
    if not audit.verified({"status":"success","raw_report":report}) or report["_appsec"]["image_id"]!=image:
        raise ValueError("Verified exact base report required")
    os_info=report.get("Metadata",{}).get("OS") or {}
    if os_info.get("Family")!="debian" or str(os_info.get("Name","")).split(".")[0] not in ("12","13"):
        raise ValueError("Native backend supports Debian 12/13 only")
    rows=apt.inventory(image)
    if "nginx" not in rows:
        raise ValueError("Initial native backend is limited to trusted nginx images")
    available=repo.availability(image,mirrors)
    if available["status"]!="repository_checked":
        raise ValueError("Approved repositories unavailable; no upgrade conclusion")
    updates=changes(available["simulation"],rows)
    # Use native Debian ordering, not lexical or PEP 440 comparison.
    for row in updates.values():
        apt.container(image,'dpkg --compare-versions "$1" lt "$2"',[row["before"],row["after"]])
    result={"schema":SCHEMA,"image_id":image,"mirror":available["mirror"],"mirror_priority":list(mirrors),
            "updates":updates,"inventory":rows,"report_sha256":hashlib.sha256(audit.input_bytes(report)).hexdigest(),
            "approval_required":bool(updates),"publication_authorized":False}
    result["plan_sha256"]=apt.plan_digest(result)
    return result


# This script is run only in a disposable trusted image. Existing source lists
# are not used. APT checks signed indices and downloaded package hashes.
DOWNLOAD=r'''
export LC_ALL=C
. /etc/os-release
test "$ID" = debian
case "$VERSION_CODENAME" in bookworm|trixie) ;; *) exit 21;; esac
key=/usr/share/keyrings/debian-archive-keyring.pgp
test -f "$key" || key=/usr/share/keyrings/debian-archive-keyring.gpg
test -f "$key"
main="$1"; security="$2"; shift 2
mkdir -p /tmp/appsec-apt-empty /tmp/appsec-download
printf 'deb [signed-by=%s] %s %s main\ndeb [signed-by=%s] %s %s-updates main\ndeb [signed-by=%s] %s %s-security main\n' "$key" "$main" "$VERSION_CODENAME" "$key" "$main" "$VERSION_CODENAME" "$key" "$security" "$VERSION_CODENAME" > /tmp/appsec-apt.list
rm -rf /var/lib/apt/lists/*
apt_safe() {
  apt-get -o Dir::Etc::sourcelist=/tmp/appsec-apt.list -o Dir::Etc::sourceparts=/tmp/appsec-apt-empty -o Acquire::https::AllowRedirect=false -o Acquire::http::AllowRedirect=false -o Acquire::Check-Valid-Until=true -o Acquire::AllowInsecureRepositories=false -o APT::Get::AllowUnauthenticated=false -o Acquire::https::Verify-Peer=true -o Acquire::https::Verify-Host=true -o Acquire::Retries=1 -o Acquire::https::Timeout=30 "$@"
}
apt_safe -o APT::Update::Error-Mode=any update
cd /tmp/appsec-download
apt_safe download "$@"
'''


def download(image,mirror,updates,dest):
    args=[]
    for name,row in sorted(updates.items()):
        if not apt.PKG.fullmatch(name) or not VERSION.fullmatch(row["after"]):
            raise ValueError("Invalid package pin")
        args.append(name+"="+row["after"])
    main,security=apt.MIRRORS[mirror]
    container="appsec-apt-download-"+uuid4().hex
    try:
        apt.run(["docker","create","--name",container,"--pull=never","--user","0:0",
                 "--security-opt","no-new-privileges:true","--pids-limit","128","--memory","1g",
                 "--entrypoint","/bin/sh",image,"-ec",DOWNLOAD,"lab",main,security,*args],60)
        apt.run(["docker","start","-a",container],600)
        state=apt.run(["docker","inspect","--format","{{.State.ExitCode}}",container]).strip()
        if state!="0":
            raise ValueError("APT download failed")
        apt.run(["docker","cp",container+":/tmp/appsec-download/.",str(dest)],180)
        files=sorted(dest.iterdir())
        if len(files)!=len(updates) or any(p.is_symlink() or not p.is_file() or p.suffix!=".deb" for p in files):
            raise ValueError("Downloaded archive set differs from approved pins")
        # Exact package identity is verified in an offline container using
        # dpkg-deb; never trust file name alone. The install result is checked too.
        hashes={}
        for p in files:
            with p.open("rb") as stream:
                hashes[p.name]=hashlib.file_digest(stream,"sha256").hexdigest()
        return hashes
    finally:
        subprocess.run(["docker","rm","-f",container],check=False,timeout=30,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


def build(plan_data,report,approved,authorized_mirrors):
    if plan_data.get("schema")!=SCHEMA or plan_data.get("plan_sha256")!=approved or apt.plan_digest(plan_data)!=approved:
        raise ValueError("Plan digest mismatch")
    if not set(plan_data["mirror_priority"])<=set(authorized_mirrors):
        raise ValueError("Approved mirror authorization revoked")
    image=plan_data["image_id"]
    # Recheck the chosen mirror only. Never silently change source after approval.
    fresh=plan(image,report,[plan_data["mirror"]])
    if not fresh["updates"] or any(fresh[k]!=plan_data[k] for k in ("image_id","mirror","updates","inventory","report_sha256")):
        raise ValueError("Upgrade plan changed; request new approval")
    base=apt.inspect(image)
    if base["Config"].get("User") not in ("","root","0","0:0",None):
        raise ValueError("Only root-default build images supported")
    uid=uuid4().hex
    tag="appsec-lab/native-base:"+uid
    output="appsec-lab/native-upgraded:"+uid
    apt.run(["docker","tag",image,tag])
    try:
        with tempfile.TemporaryDirectory(prefix="appsec-native-apt-") as tmp:
            root=Path(tmp)
            dest=root/"debs";dest.mkdir()
            hashes=download(image,plan_data["mirror"],plan_data["updates"],dest)
            # BuildKit bind mount keeps downloaded archives out of the final
            # layer. No network and no downloads while installing.
            # Validate every .deb name/version/arch before invoking apt.
            checks=[]
            for name,row in sorted(plan_data["updates"].items()):
                bare=name.split(":")[0]
                checks.append(bare+"="+row["after"])
            if len(set(checks))!=len(checks):
                raise ValueError("Ambiguous multiarch upgrade")
            expected=" ".join(sorted(checks))
            # Names/versions were validated above; compare package metadata from
            # the actual archives, not filenames.
            dockerfile=(
                "ARG BASE_IMAGE=appsec-lab/base:invalid\nFROM ${BASE_IMAGE}\n"
                "RUN --mount=type=bind,source=debs,target=/tmp/appsec-debs,readonly "
                "set -eu; export LC_ALL=C; "
                "actual=$(for f in /tmp/appsec-debs/*.deb; do "
                "p=$(dpkg-deb -f \"$f\" Package); v=$(dpkg-deb -f \"$f\" Version); "
                "a=$(dpkg-deb -f \"$f\" Architecture); test \"$a\" = amd64 || test \"$a\" = all; "
                "printf '%s=%s\\n' \"$p\" \"$v\"; done | sort | paste -sd ' '); "
                "test \"$actual\" = '"+expected+"'; "
                "apt-get -y --no-download --no-remove --only-upgrade install /tmp/appsec-debs/*.deb; "
                "test -z \"$(dpkg --audit)\"; nginx -t\n")
            (root/"Dockerfile").write_text(dockerfile)
            apt.run(["docker","buildx","build","--builder","default","--progress","plain","--load",
                     "--pull=false","--network=none","--no-cache","--build-arg","BASE_IMAGE="+tag,
                     "-t",output,tmp],1800,capture=False)
        candidate_id=apt.run(["docker","image","inspect","--format","{{.Id}}",output]).strip()
        candidate=apt.inspect(candidate_id)
        layers=base["RootFS"]["Layers"]
        if candidate_id==image or candidate["RootFS"]["Layers"][:len(layers)]!=layers:
            raise ValueError("Candidate lineage mismatch")
        if any(base["Config"].get(k)!=candidate["Config"].get(k) for k in CONFIG_KEYS):
            raise ValueError("Runtime config changed")
        expected={p:v["version"] for p,v in plan_data["inventory"].items()}
        expected.update({p:v["after"] for p,v in plan_data["updates"].items()})
        actual={p:v["version"] for p,v in apt.inventory(candidate_id).items()}
        if actual!=expected:
            raise ValueError("Actual installed versions differ from approved upgrade")
        return {"schema":"appsec.native-apt-candidate/v1","status":"candidate_prepared",
                "base_image_id":image,"candidate":output,"candidate_image_id":candidate_id,
                "approved_plan_sha256":approved,"mirror":plan_data["mirror"],"updated_packages":plan_data["updates"],
                "downloaded_archives_sha256":hashes,"rescan_required":True,
                "functional_test_passed":False,"publication_authorized":False,"historical_layers_removed":False}
    finally:
        subprocess.run(["docker","image","rm",tag],check=False,timeout=30,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
