"""Explicit local-only external APT trial. No publication or CVE suppression."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from uuid import uuid4
from . import approved_binaries as ab, apt_optimization as apt, backport_trial as bp
from . import native_apt, independent_scan, fix_discovery as vendor, job_watch
from .workflow_control import StopRequested

def enabled():
    return os.getenv("APPSEC_V4_EXTERNAL_TRIAL","false").lower()=="true"

def select(plan,catalog):
    if catalog.get("status")!="completed" or not ab.DIGEST.fullmatch(catalog.get("policy_sha256") or ""):
        return None
    # Explicit operator priority between repositories; no mixed source groups.
    for repo in catalog.get("repositories") or []:
        if repo.get("status")!="completed" or repo.get("advisory_status")!="operator_snapshot_matched":
            continue
        groups={}
        for c in repo.get("candidates") or []:
            groups.setdefault(c["installed_source"],[]).append(c)
        ranked=[]
        for source,rows in groups.items():
            if any(c.get("status")!="signed_binary_found" or c.get("source_package")!=source
                or c.get("architecture") not in ("amd64","all") or not ab.DIGEST.fullmatch(c.get("sha256") or "")
                or not isinstance(c.get("size"),int) or not 0<c["size"]<=256*1024*1024
                or not apt.PKG.fullmatch(c["package"]) or not native_apt.VERSION.fullmatch(c["candidate"])
                for c in rows):
                continue
            updates={c["package"]:{"before":c["before"],"after":c["candidate"]} for c in rows}
            sim=(repo.get("simulations") or {}).get(source,{})
            if (len(updates)!=len(rows) or sim.get("status")!="existing_package_upgrades_only" or sim.get("changes")!=updates
                or any(n in plan["updates"] or plan["inventory"].get(n,{}).get("version")!=u["before"]
                       or vendor.ge(u["before"],u["after"]) for n,u in updates.items())
                or len({c["sha256"] for c in rows})!=len(rows) or sum(c["size"] for c in rows)>512*1024*1024):
                continue
            claims=sorted({(c["package"].split(":")[0],m["id"]) for c in rows for m in c.get("operator_advisory_matches") or []})
            if claims:
                ranked.append((-len(claims),source,updates,rows,claims))
        if ranked:
            _,source,updates,rows,claims=sorted(ranked,key=lambda x:(x[0],x[1]))[0]
            return {"repository":repo,"source":source,"updates":updates,"rows":rows,"claims":claims,
                    "policy_sha256":catalog["policy_sha256"]}
    return None

def authorization(chosen,root=ab.ROOT):
    policy=ab.read_bounded(root/"approved-binaries.json",64*1024)
    if hashlib.sha256(policy).hexdigest()!=chosen["policy_sha256"]:
        raise ValueError("External repository policy changed")
    repo=chosen["repository"]
    rows=ab.validate(json.loads(policy))
    row=next((r for r in rows if r["id"]==repo["id"]),None)
    if not row or any(row[k]!=repo.get(k if k!="url" else "repository") for k in ("url","suite","component","keyring_sha256","advisory_sha256")):
        raise ValueError("External repository authorization changed")
    key=ab.read_bounded(root/(row["id"]+".gpg"),1024*1024)
    if hashlib.sha256(key).hexdigest()!=row["keyring_sha256"]:
        raise ValueError("External keyring changed")
    claims=ab.advisories(ab.read_bounded(root/(row["id"]+".advisories.json"),1024*1024),row)
    for c in chosen["rows"]:
        name=c["package"].split(":")[0]
        if name not in row["packages"]:
            raise ValueError("Package no longer authorized")
        for m in c.get("operator_advisory_matches") or []:
            if claims.get((name,c["candidate"],c["architecture"],c["sha256"],m["id"]))!=m["advisory_url"]:
                raise ValueError("Advisory assertion changed")
    return row,key

def archive_script(count,total):
    prefix=ab.PROBE.split(': > "$work/pins"',1)[0]
    suffix=bp.archive_script("trixie").split(': > "$work/expected"',1)[1]
    if not 1<=count<=64 or not 0<total<=512*1024*1024:
        raise ValueError("External archive limits invalid")
    return prefix+': > "$work/expected"'+suffix+f'\n' + f'test "$(find /tmp/appsec-download -maxdepth 1 -type f -name \'*.deb\' | wc -l)" -eq {count}\n' + f'test "$(du -sb /tmp/appsec-download | cut -f1)" -le {total+1048576}\n'

def verify_archives(dest,rows):
    files=sorted(dest.iterdir())
    expected={c["sha256"]:c["size"] for c in rows}
    if len(expected)!=len(rows) or len(files)!=len(rows):
        raise ValueError("External archive count mismatch")
    hashes={}
    for path in files:
        if path.is_symlink() or not path.is_file() or path.suffix!=".deb" or path.stat().st_size not in expected.values():
            raise ValueError("Unexpected external archive")
        h=hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda:stream.read(1024*1024),b""):
                h.update(block)
        digest=h.hexdigest()
        if expected.get(digest)!=path.stat().st_size:
            raise ValueError("External archive digest or size mismatch")
        hashes[path.name]=digest
    if sorted(hashes.values())!=sorted(expected):
        raise ValueError("External archive digest set mismatch")
    return hashes

def download(image,updates,dest,chosen):
    if updates!=chosen["updates"]:
        raise ValueError("External transaction changed")
    row,key=authorization(chosen)
    args=[n+"="+u["after"] for n,u in sorted(updates.items())]
    name="appsec-external-download-"+uuid4().hex
    try:
        with tempfile.TemporaryDirectory(prefix="appsec-external-key-") as tmp:
            path=Path(tmp)/"key.gpg"
            path.write_bytes(key)
            path.chmod(0o644)
            apt.run(["docker","create","--name",name,"--pull=never","--user","0:0",
                     "--security-opt","no-new-privileges:true","--pids-limit","128","--memory","1g",
                     "--entrypoint","/bin/sh",image,"-ec",archive_script(len(chosen["rows"]),sum(c["size"] for c in chosen["rows"])),"trial",row["url"],row["component"],row["suite"],*args],60)
            apt.run(["docker","cp",str(path),name+":/tmp/appsec-vendor-key.gpg"],30)
            apt.run(["docker","start","-a",name],420)
            if apt.run(["docker","inspect","--format","{{.State.ExitCode}}",name]).strip()!="0":
                raise ValueError("External exact download failed")
            # Bound bytes and entries before copying out of the disposable container.
            apt.run(["docker","cp",name+":/tmp/appsec-download/.",str(dest)],180)
        return verify_archives(dest,chosen["rows"])
    finally:
        subprocess.run(["docker","rm","-f",name],check=False,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

def observed_claims(reports,chosen):
    def index(report):
        return {(v["PkgName"].split(":")[0],v["VulnerabilityID"])
                for t in report["raw_report"]["Results"] if t.get("Class")=="os-pkgs" and t.get("Type")=="debian"
                for v in t.get("Vulnerabilities") or []}
    before,after=map(index,reports)
    return [{"package":p,"id":cve} for p,cve in chosen["claims"] if (p,cve) in before-after]

def attempt(plan,report,catalog,stable,authorized):
    if not enabled():
        return stable,{"status":"disabled"}
    if not independent_scan.enabled():
        return stable,{"status":"blocked","message":"Independent scanning required"}
    trial=None
    accepted=False
    chosen=None
    try:
        chosen=select(plan,catalog)
        if not chosen or plan["mirror"] not in authorized:
            return stable,{"status":"not_attempted","message":"No eligible exact external source group"}
        authorization(chosen)
        baseline=stable["candidate_image_id"] if stable else plan["image_id"]
        inventory=apt.inventory(baseline)
        expected={n:v["version"] for n,v in plan["inventory"].items()}
        expected.update({n:u["after"] for n,u in plan["updates"].items()})
        if {n:v["version"] for n,v in inventory.items()}!=expected:
            raise ValueError("Stable baseline inventory changed")
        incremental={**plan,"image_id":baseline,"inventory":inventory,"updates":chosen["updates"],
                     "external_policy_sha256":chosen["policy_sha256"],"external_repository_id":chosen["repository"]["id"],
                     "external_archive_sha256":sorted(c["sha256"] for c in chosen["rows"])}
        incremental["plan_sha256"]=apt.plan_digest(incremental)
        job_watch.emit("external_trial")
        trial=native_apt._build_exact(incremental,generic=True,downloader=lambda image,updates,dest:download(image,updates,dest,chosen),
                                     required_hashes=incremental["external_archive_sha256"])
        from .optimization import offline_compare
        reports,hashes,scanner=offline_compare([baseline,trial["candidate_image_id"]],report["_appsec"]["scanner_image"])
        a,_,_=independent_scan.scan(baseline,reports[0]["raw_report"])
        b,_,_=independent_scan.scan(trial["candidate_image_id"],reports[1]["raw_report"])
        result=bp.gate(reports,a,b)
        observed=observed_claims(reports,chosen)
        if not observed:
            result["status"]="rejected"
            result["blockers"].append("no_matching_advisory_cve_reduction")
        authorization(chosen)
        result.update(repository_id=chosen["repository"]["id"],source=chosen["source"],updates=chosen["updates"],
                      policy_sha256=chosen["policy_sha256"],observed_advisory_cves=observed,
                      baseline_image_id=baseline,trial_image_id=trial["candidate_image_id"],trial_plan_sha256=incremental["plan_sha256"],
                      downloaded_archives_sha256=trial["downloaded_archives_sha256"],
                      trivy_db_files_sha256=hashes,trivy_image_id=scanner,independent_db_files_sha256=a.get("db_files_sha256"))
        job_watch.checkpoint()
        if result["status"]=="selected_local_candidate":
            accepted=True
            return trial,result
        return stable,result
    except StopRequested:
        raise
    except (ValueError,RuntimeError,OSError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        from .errors import safe_message
        return stable,{"status":"rejected","message":safe_message(exc,"patch_build"),"publication_authorized":False}
    finally:
        if trial and not accepted:
            bp.cleanup(trial)
