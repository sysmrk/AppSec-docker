"""Opt-in EL9 native DNF4/RPM pilot with pinned package-signing keys."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from uuid import uuid4
from . import approved_binaries as ab, apt_optimization as apt, native_apt
from . import backport_trial, independent_scan, remediation_audit as audit, job_watch
from .workflow_control import StopRequested

ROOT=Path("/vendor-snapshots")
FAMILIES={"redhat":"rhel","rocky":"rocky","alma":"almalinux","oracle":"ol"}
REPOS={
    "rhel":("https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/baseos/os",
            "https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/appstream/os"),
    "rocky":("https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/",
             "https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/"),
    "almalinux":("https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/",
                 "https://repo.almalinux.org/almalinux/9/AppStream/x86_64/os/"),
    "ol":("https://yum.oracle.com/repo/OracleLinux/OL9/baseos/latest/x86_64/",
          "https://yum.oracle.com/repo/OracleLinux/OL9/appstream/x86_64/"),
}
TOKEN=re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~^-]{0,191}")
KEY=re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
MAX_BYTES=512*1024*1024
QUERY=r"%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n"

def enabled():
    return os.getenv("APPSEC_V4_RPM_TRIAL","false").lower()=="true"

def distro(report):
    info=(report.get("Metadata") or {}).get("OS") or {}
    return FAMILIES.get(info.get("Family")) if str(info.get("Name","")).split(".")[0]=="9" else None

def supports(report):
    return distro(report) in REPOS

def policy(kind,root=ROOT):
    data=ab.read_bounded(root/("rpm-"+kind+"-keys.json"),65536)
    doc=json.loads(data)
    if not isinstance(doc,dict) or set(doc)!={"schema","distribution","major","keys"} or doc["schema"]!="appsec.rpm-keys/v1" or doc["distribution"]!=kind or doc["major"]!="9":
        raise ValueError("Invalid RPM trust policy")
    keys=doc["keys"]
    if not isinstance(keys,dict) or not 1<=len(keys)<=16:
        raise ValueError("Explicit RPM signing keys required")
    content={}
    for name,sha in keys.items():
        if not KEY.fullmatch(name) or not isinstance(sha,str) or not ab.DIGEST.fullmatch(sha):
            raise ValueError("Invalid RPM key identity")
        raw=ab.read_bounded(root/("rpm-"+kind+"-keys")/name,65536)
        if hashlib.sha256(raw).hexdigest()!=sha:
            raise ValueError("RPM key digest mismatch")
        content[name]=raw
    return hashlib.sha256(data).hexdigest(),content

def parse_inventory(output):
    rows={}
    for line in output.splitlines():
        n,e,v,r,a=line.split("\t")
        if not TOKEN.fullmatch(n) or not e.isdigit() or not TOKEN.fullmatch(v) or not TOKEN.fullmatch(r) or a not in ("x86_64","noarch"):
            # Public keys are represented as RPM database pseudo-packages.
            if n!="gpg-pubkey" or a!="(none)" or not TOKEN.fullmatch(v) or not TOKEN.fullmatch(r) or not e.isdigit():
                raise ValueError("Unsupported RPM identity or architecture")
        name=n+":"+a if n!="gpg-pubkey" else n+":"+v+":"+r
        if name in rows:
            raise ValueError("Multiple installed RPM versions not supported")
        rows[name]={"name":n,"epoch":e,"version":v,"release":r,"architecture":a}
    if not rows or len(rows)>2000:
        raise ValueError("Invalid RPM inventory size")
    return rows

def inventory(image,kind):
    out=apt.container(image,r'''
export LC_ALL=C
. /etc/os-release
test "$ID" = "$1"
test "${VERSION_ID%%.*}" = 9
test "$(uname -m)" = x86_64
rpm -qa --qf "$2"
''',[kind,QUERY])
    return parse_inventory(out)

# Run inside the trusted disposable target only. DNF4 resolves the complete
# transaction using official same-major repos. RPM labelCompare is authoritative.
STAGE=r'''
import dnf, rpm, os, sys, shutil, json, subprocess
kind, url1, url2 = sys.argv[1:]
output="/tmp/appsec-rpm-output"
if os.path.exists(output): raise RuntimeError("Stage path exists")
os.mkdir(output)
def ident(p):
    return [p.name,str(p.epoch or 0),p.version,p.release,p.arch]
with dnf.Base() as b:
    c=b.conf
    c.cachedir="/tmp/appsec-rpm-cache"
    c.persistdir="/tmp/appsec-rpm-persist"
    c.logdir="/tmp"
    c.reposdir=[]
    c.plugins=False
    c.substitutions["releasever"]="9"
    c.module_platform_id="platform:el9"
    c.install_weak_deps=False
    c.best=True
    c.obsoletes=False
    c.gpgcheck=True
    for i,url in enumerate((url1,url2)):
        repo=b.repos.add_new_repo("appsec-"+str(i),c,baseurl=[url])
        repo.sslverify=True
        repo.gpgcheck=True
        repo.skip_if_unavailable=False
        repo.enable()
    b.fill_sack(load_system_repo=True)
    class UnsafeClosure(RuntimeError):
        pass
    def closure():
        install=list(b.transaction.install_set)
        remove=list(b.transaction.remove_set)
        old={}
        for p in remove:
            row=ident(p); key=(row[0],row[4])
            if key in old: raise UnsafeClosure("Duplicate RPM removal")
            old[key]=row
        new={}
        for p in install:
            row=ident(p); key=(row[0],row[4])
            if key in new or key not in old or row[4] not in ("x86_64","noarch") or rpm.labelCompare(tuple(old[key][1:4]),tuple(row[1:4]))>=0:
                raise UnsafeClosure("Not an exact existing-package upgrade")
            if p.reponame not in ("appsec-0","appsec-1"):
                raise UnsafeClosure("Unapproved RPM origin")
            new[key]=row
        if set(old)!=set(new) or len(new)>128 or sum(p.downloadsize for p in install)>512*1024*1024:
            raise UnsafeClosure("RPM transaction closure or size invalid")
        return install,old
    try:
        b.upgrade_all()
        b.resolve(allow_erasing=False)
        install,old=closure()
        scope="all"
    except (UnsafeClosure,dnf.exceptions.DepsolveError):
        # A full transaction can require new dependencies. Try bounded
        # source cohorts, accumulating only closures which remain safe.
        # No dependency or signature checks are relaxed.
        groups={}
        for p in b.sack.query().upgrades():
            groups.setdefault(p.source_name or p.name,set()).add(p.name)
        ranked=sorted(groups,key=lambda n:(-len(groups[n]),n))
        selected=set()
        for group in ranked[:16]:
            trial=selected|groups[group]
            b.reset(goal=True)
            try:
                for name in sorted(trial): b.upgrade(name)
                b.resolve(allow_erasing=False)
                chosen,_=closure()
                if chosen: selected=trial
            except (UnsafeClosure,dnf.exceptions.DepsolveError,dnf.exceptions.MarkingError):
                continue
        if not selected:
            raise RuntimeError("No verified exact RPM upgrade closure in bounded source cohort review")
        b.reset(goal=True)
        for name in sorted(selected): b.upgrade(name)
        b.resolve(allow_erasing=False)
        install,old=closure()
        scope="bounded_source_cohort_subset"
    print("@@SCOPE "+scope)
    if install:
        b.download_packages(install)
    records=[]
    for p in install:
        row=ident(p)
        path=p.localPkg()
        if not os.path.isfile(path): raise RuntimeError("RPM download missing")
        name=os.path.basename(path)
        dst=os.path.join(output,name)
        if os.path.exists(dst): raise RuntimeError("Duplicate RPM archive")
        shutil.copyfile(path,dst)
        records.append({"before":old[(row[0],row[4])],"after":row,"filename":name,"repo":p.reponame})
    print("@@PLAN "+json.dumps(records,separators=(",",":")))
'''

VERIFY=r'''
set -eu
export LC_ALL=C
db=$(mktemp -d)
trap 'rm -rf "$db"' EXIT
rpm --dbpath "$db" --initdb
for k in /tmp/appsec-rpm-keys/*; do rpm --dbpath "$db" --import "$k"; done
for f in /tmp/appsec-rpm-archives/*.rpm; do
  result=$(rpmkeys --dbpath "$db" --checksig --verbose "$f")
  printf '%s\n' "$result" | grep -Eiq 'Signature.*: OK$'
  if printf '%s\n' "$result" | grep -Eiq 'NOKEY|NOT OK|BAD|NOTTRUSTED'; then exit 31; fi
done
'''

def parse_plan(output,before):
    markers=[x[len("@@PLAN "):] for x in output.splitlines() if x.startswith("@@PLAN ")]
    if len(markers)!=1:
        raise ValueError("Missing RPM solver evidence")
    records=json.loads(markers[0])
    if not isinstance(records,list) or len(records)>128:
        raise ValueError("Invalid RPM transaction size")
    updates={};names=set()
    for row in records:
        if not isinstance(row,dict) or set(row)!={"before","after","filename","repo"}:
            raise ValueError("Invalid RPM transaction record")
        old,new=row["before"],row["after"]
        if not all(isinstance(x,list) and len(x)==5 and all(isinstance(v,str) for v in x) for x in (old,new)):
            raise ValueError("Malformed RPM identity")
        a,b=(next(iter(parse_inventory("\t".join(x)).values())) for x in (old,new))
        name=a["name"]+":"+a["architecture"]
        filename=row["filename"]
        if name in updates or a!=before.get(name) or a["name"]!=b["name"] or a["architecture"]!=b["architecture"] or a==b or a["name"]=="gpg-pubkey" or row["repo"] not in ("appsec-0","appsec-1") or filename!=f'{b["name"]}-{b["version"]}-{b["release"]}.{b["architecture"]}.rpm' or filename in names:
            raise ValueError("RPM transaction not bound to installed packages")
        names.add(filename)
        updates[name]={"before":f'{a["epoch"]}:{a["version"]}-{a["release"]}',"after":f'{b["epoch"]}:{b["version"]}-{b["release"]}',"identity":b,"filename":filename,"repo":row["repo"]}
    return updates

def stage(image,kind,dest,before):
    name="appsec-rpm-stage-"+uuid4().hex
    script=r'''
set -eu
. /etc/os-release
test "$ID" = "$1"
test "${VERSION_ID%%.*}" = 9
exec /usr/bin/python3 -c "$4" "$1" "$2" "$3"
'''
    try:
        apt.run(["docker","create","--name",name,"--pull=never","--user","0:0",
                 "--security-opt","no-new-privileges:true","--pids-limit","128","--memory","2g",
                 "--entrypoint","/bin/sh",image,"-ec",script,"stage",kind,*REPOS[kind],STAGE],60)
        output=apt.run(["docker","start","-a",name],600)
        if apt.run(["docker","inspect","--format","{{.State.ExitCode}}",name]).strip()!="0":
            raise ValueError("RPM staging failed")
        updates=parse_plan(output,before)
        scopes=[x.split(" ",1)[1] for x in output.splitlines() if x.startswith("@@SCOPE ")]
        if len(scopes)!=1 or scopes[0] not in ("all","bounded_source_cohort_subset"):
            raise ValueError("RPM solver scope missing")
        if updates:
            apt.run(["docker","cp",name+":/tmp/appsec-rpm-output/.",str(dest)],180)
        return updates,scopes[0]
    finally:
        subprocess.run(["docker","rm","-f",name],check=False,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

def hashes(dest,updates):
    files=list(dest.iterdir())
    if {p.name for p in files}!={v["filename"] for v in updates.values()} or any(p.is_symlink() or not p.is_file() or not 0<p.stat().st_size<=MAX_BYTES for p in files) or sum(p.stat().st_size for p in files)>MAX_BYTES:
        raise ValueError("RPM archive set or size mismatch")
    result={}
    for p in files:
        h=hashlib.sha256()
        with p.open("rb") as stream:
            for block in iter(lambda:stream.read(1024*1024),b""):
                h.update(block)
        result[p.name]=h.hexdigest()
    return result

def validate_after(before,after,updates):
    expected={**before,**{k:v["identity"] for k,v in updates.items()}}
    if after!=expected:
        raise ValueError("Actual RPM inventory differs from plan")

def build(image,report,root=ROOT):
    kind=distro(report)
    if kind not in REPOS or not audit.verified({"status":"success","raw_report":report}) or report["_appsec"]["image_id"]!=image:
        raise ValueError("Verified EL9 scan required")
    base=apt.inspect(image)
    if base["Config"].get("User") not in ("","root","0","0:0",None):
        raise ValueError("Root-default RPM images only")
    if kind=="rhel" and (base["Config"].get("Labels") or {}).get("com.redhat.component")!="ubi9-container":
        raise ValueError("Only full public UBI9 images supported; entitled RHEL is not UBI")
    trust,keys=policy(kind,root)
    before=inventory(image,kind)
    uid=uuid4().hex;tag="appsec-lab/rpm-base:"+uid;output="appsec-lab/rpm-upgraded:"+uid
    accepted=False
    try:
        with tempfile.TemporaryDirectory(prefix="appsec-native-rpm-") as tmp:
            ctx=Path(tmp)
            rpms=ctx/"archives";rpms.mkdir()
            job_watch.emit("rpm_plan")
            updates,scope=stage(image,kind,rpms,before)
            if not updates:
                return None,{"backend":"native_rpm","status":"no_updates","distribution":kind,"publication_authorized":False}
            archive_hashes=hashes(rpms,updates)
            keydir=ctx/"keys";keydir.mkdir()
            for n,data in keys.items(): (keydir/n).write_bytes(data)
            (ctx/"checksums").write_text("".join(h+"  /tmp/appsec-rpm-archives/"+n+"\n" for n,h in sorted(archive_hashes.items())))
            (ctx/"verify.sh").write_text(VERIFY)
            # Verify each archive header identity before executing RPM scriptlets.
            expected="".join("\t".join(v["identity"][k] for k in ("name","epoch","version","release","architecture"))+"\n" for v in updates.values())
            (ctx/"expected").write_text(expected)
            (ctx/"Dockerfile").write_text(
                "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n"
                "RUN --mount=type=bind,source=archives,target=/tmp/appsec-rpm-archives,readonly "
                "--mount=type=bind,source=keys,target=/tmp/appsec-rpm-keys,readonly "
                "--mount=type=bind,source=checksums,target=/tmp/appsec-checksums,readonly "
                "--mount=type=bind,source=expected,target=/tmp/appsec-expected,readonly "
                "--mount=type=bind,source=verify.sh,target=/tmp/appsec-verify.sh,readonly "
                "set -eu; export LC_ALL=C; sha256sum -c /tmp/appsec-checksums; sh /tmp/appsec-verify.sh; "
                "work=$(mktemp -d); trap 'rm -rf \"$work\"' EXIT; "
                "rpm -qp --qf '"+QUERY+"' /tmp/appsec-rpm-archives/*.rpm | sort > \"$work/actual\"; "
                "sort /tmp/appsec-expected > \"$work/expected\"; test \"$(sha256sum \"$work/actual\" | cut -d' ' -f1)\" = \"$(sha256sum \"$work/expected\" | cut -d' ' -f1)\"; "
                "rpm -U --test /tmp/appsec-rpm-archives/*.rpm; rpm -U /tmp/appsec-rpm-archives/*.rpm\n")
            data={"backend":"native_rpm","distribution":kind,"release":"9","image_id":image,"updates":updates,
                  "key_policy_sha256":trust,"archives_sha256":archive_hashes,"repositories":REPOS[kind],"selection_scope":scope,"publication_authorized":False}
            data["plan_sha256"]=apt.plan_digest(data)
            if policy(kind,root)[0]!=trust: raise ValueError("RPM trust changed")
            apt.run(["docker","tag",image,tag])
            job_watch.emit("rpm_build")
            apt.run(["docker","buildx","build","--builder","default","--progress","plain","--load","--pull=false","--network=none","--no-cache","--build-arg","BASE_IMAGE="+tag,"-t",output,tmp],1800,capture=False)
        iid=apt.run(["docker","image","inspect","--format","{{.Id}}",output]).strip()
        after=apt.inspect(iid)
        layers=base["RootFS"]["Layers"]
        if iid==image or after["RootFS"]["Layers"][:len(layers)]!=layers or any(base["Config"].get(k)!=after["Config"].get(k) for k in native_apt.CONFIG_KEYS):
            raise ValueError("RPM candidate lineage or runtime configuration changed")
        validate_after(before,inventory(iid,kind),updates)
        if inventory(image,kind)!=before or policy(kind,root)[0]!=trust:
            raise ValueError("Original RPM image or key policy changed")
        candidate={"schema":"appsec.native-rpm-candidate/v1","candidate":output,"candidate_image_id":iid,
                   "base_image_id":image,"updated_packages":updates,"approved_plan_sha256":data["plan_sha256"],
                   "downloaded_archives_sha256":archive_hashes,"functional_test_passed":False,"publication_authorized":False}
        accepted=True
        return candidate,{**data,"status":"candidate_prepared"}
    finally:
        subprocess.run(["docker","image","rm",tag],check=False,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if not accepted: subprocess.run(["docker","image","rm",output],check=False,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

def attempt(image,report):
    if not enabled() or not independent_scan.enabled():
        return None,{"status":"blocked","backend":"native_rpm","message":"RPM trial and independent scan must be enabled","publication_authorized":False}
    candidate=None
    accepted=False
    try:
        candidate,data=build(image,report)
        if not candidate: return None,data
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
    except (OSError,ValueError,RuntimeError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        from .errors import safe_message
        return None,{"status":"blocked","backend":"native_rpm","message":safe_message(exc,"patch_build"),"publication_authorized":False}
    finally:
        if candidate and not accepted: backport_trial.cleanup(candidate)
