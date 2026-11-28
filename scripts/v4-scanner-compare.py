#!/usr/bin/env python3
"""Read-only Syft/Grype comparison of local images; no Docker socket or egress in scanners."""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from uuid import uuid4

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"runner"))
from appsecctl import benchmark as bench, scan_evidence


def manifest(root):
    files={}
    def walk_error(exc):
        raise exc
    # pathlib.rglob can silently skip unreadable subdirectories.
    for directory,dirs,names in os.walk(root,onerror=walk_error,followlinks=False):
        for name in sorted(dirs+names):
            p=Path(directory)/name
            if p.is_symlink() or not (p.is_dir() or p.is_file()):
                raise ValueError("Unsupported Grype cache entry")
            if p.is_file():
                with p.open("rb") as stream:
                    files[p.relative_to(root).as_posix()]=bench.hash_stream(stream)
    if not any(k.endswith("/vulnerability.db") or k=="vulnerability.db" for k in files):
        raise ValueError("Grype vulnerability database missing; prepare cache first")
    return files


def tool(image, args, mounts=(), env=(), timeout=300):
    name="appsec-v4-scanner-"+uuid4().hex
    cmd=["docker","run","--rm","--name",name,"--pull=never","--network=none",
         "--user",f"{os.getuid()}:{os.getgid()}","--cap-drop","ALL","--security-opt","no-new-privileges:true",
         "--read-only","--tmpfs","/tmp:rw,nosuid,nodev,mode=1777,size=256m","--memory","2g","--pids-limit","128"]
    for host,target,readonly in mounts:
        cmd.extend(["--mount",f"type=bind,src={host},dst={target}"+(",readonly" if readonly else "")])
    for value in env:
        cmd.extend(["-e",value])
    try:
        return subprocess.run([*cmd,image,*args],check=True,stdout=subprocess.PIPE,timeout=timeout).stdout
    except (subprocess.TimeoutExpired,KeyboardInterrupt):
        subprocess.run(["docker","rm","-f",name],check=False,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        raise


def findings(report):
    if not isinstance(report.get("matches"),list):
        raise ValueError("Malformed Grype output")
    counts=Counter()
    ids=set()
    fixed=[]
    for match in report["matches"]:
        v,a=match["vulnerability"],match["artifact"]
        if not v.get("id") or not a.get("name") or not a.get("version"):
            raise ValueError("Incomplete Grype match")
        counts[str(v.get("severity") or "Unknown").upper()]+=1
        ids.add(v["id"])
        fix=v.get("fix") or {}
        if fix.get("state")=="fixed" and fix.get("versions"):
            fixed.append({"id":v["id"],"package":a["name"],"installed":a["version"],
                          "type":a.get("type"),"namespace":v.get("namespace"),"fixed_versions":fix["versions"]})
    return {"matches":len(report["matches"]),"severity":dict(counts),"unique_advisory_ids":sorted(ids),
            "reported_fix_matches":fixed,"ignored_matches":len(report.get("ignoredMatches") or [])}


def match_delta(before,after):
    """Compare exact advisory/package/namespace/type occurrences, not aliases."""
    def index(report):
        result=Counter()
        for match in report["matches"]:
            v,a=match["vulnerability"],match["artifact"]
            result[(v["id"],a["name"],a.get("type") or "",v.get("namespace") or "")]+=1
        return result
    def rows(values):
        return [{"id":k[0],"package":k[1],"type":k[2],"namespace":k[3],"count":n}
                for k,n in sorted(values.items())]
    a,b=index(before),index(after)
    return {"no_longer_reported":rows(a-b),"introduced":rows(b-a),
            "no_longer_reported_count":sum((a-b).values()),"introduced_count":sum((b-a).values()),
            "method":"exact advisory/package/type/namespace occurrence counts; ambiguous instances not resolved"}


def trivy_ids(path,image):
    report=json.loads(path.read_text())
    scan_evidence.validate_report(report,image)
    return {v["VulnerabilityID"] for r in report["Results"] for v in r.get("Vulnerabilities") or []}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image",required=True,action="append",help="Local image; repeat to compare")
    p.add_argument("--syft",required=True,help="Preloaded official or approved mirrored Syft image")
    p.add_argument("--grype",required=True,help="Preloaded official or approved mirrored Grype image")
    p.add_argument("--grype-cache",required=True,type=Path,help="Prepared Grype DB directory; stop writers")
    p.add_argument("--trivy-report",action="append",type=Path,default=[],help="Optional existing raw Trivy report per image, in the same order")
    p.add_argument("--output",required=True,type=Path)
    p.add_argument("--timeout",type=int,default=600)
    args=p.parse_args(argv)
    if not 1<=len(args.image)<=8 or not 1<=args.timeout<=3600 or len(args.trivy_report) not in (0,len(args.image)):
        p.error("1–8 images, optional matching Trivy reports, timeout 1–3600")
    os.umask(0o077)
    ids=[scan_evidence.local_image_id(i) for i in args.image]
    if len(set(ids))!=len(ids):
        p.error("Duplicate immutable image")
    syft,grype=map(scan_evidence.local_image_id,(args.syft,args.grype))
    cache=args.grype_cache.resolve(strict=True)
    hashes=manifest(cache)
    out=args.output.resolve()
    out.mkdir(mode=0o700,parents=True,exist_ok=False)
    env=("GRYPE_DB_CACHE_DIR=/db","GRYPE_DB_AUTO_UPDATE=false","GRYPE_DB_VALIDATE_AGE=true",
         "GRYPE_DB_VALIDATE_BY_HASH_ON_START=true","GRYPE_DB_MAX_ALLOWED_BUILT_AGE=72h","GRYPE_CHECK_FOR_APP_UPDATE=false")
    with tempfile.TemporaryDirectory(prefix="appsec-v4-scanners-") as tmp:
        work=Path(tmp)
        frozen=work/"db"
        shutil.copytree(cache,frozen)
        if manifest(frozen)!=hashes or manifest(cache)!=hashes:
            raise RuntimeError("Grype DB changed while snapshotting")
        db_mount=(frozen,"/db",False)
        status=json.loads(tool(grype,["db","status","-o","json"],[db_mount],env,args.timeout))
        bench.write_json(out/"manifest.json",{"syft_image_id":syft,"grype_image_id":grype,"grype_db_files_sha256":hashes,
            "grype_db_status":status,"images":[{"ref":r,"id":i} for r,i in zip(args.image,ids)],
            "scope":"squashed image filesystem; offline scanners; no image execution"})
        rows=[]
        baseline_report=None
        for n,(ref,iid) in enumerate(zip(args.image,ids),1):
            t=time.monotonic()
            archive=work/"image.tar"
            sbom_path=work/"sbom.json"
            try:
                subprocess.run(["docker","image","save","--output",str(archive),iid],check=True,timeout=args.timeout)
                data=tool(syft,["scan","docker-archive:/image.tar","-o","syft-json"],[(archive,"/image.tar",True)],
                          ["SYFT_CHECK_FOR_APP_UPDATE=false","XDG_CACHE_HOME=/tmp/cache","HOME=/tmp"],args.timeout)
                sbom=json.loads(data)
                if not isinstance(sbom.get("artifacts"),list) or not sbom["artifacts"]:
                    raise ValueError("Empty Syft inventory; no zero-risk conclusion")
                reported=(sbom.get("source",{}).get("metadata") or {}).get("imageID")
                if reported and reported!=iid:
                    raise ValueError(f"Syft image identity mismatch: expected {iid}; reported {reported!r}")
                sbom_path.write_bytes(data)
                report=json.loads(tool(grype,["sbom:/sbom.json","-o","json"],[(sbom_path,"/sbom.json",True),db_mount],env,args.timeout))
                if manifest(frozen)!=hashes:
                    raise RuntimeError("Frozen Grype DB changed during scan")
                result=findings(report)
                if baseline_report is None:
                    baseline_report=report
                else:
                    result["grype_delta_from_original"]=match_delta(baseline_report,report)
                result.update(image_id=iid,reference=ref,syft_packages=len(sbom["artifacts"]),
                              syft_reported_image_id=reported,sbom_sha256=hashlib.sha256(data).hexdigest(),
                              package_types=dict(Counter(a.get("type","unknown") for a in sbom["artifacts"])),
                              seconds=round(time.monotonic()-t,3))
                if args.trivy_report:
                    old=trivy_ids(args.trivy_report[n-1],iid)
                    new=set(result["unique_advisory_ids"])
                    # Exact advisory ID only, no CVE alias or package equivalence claim.
                    result["trivy_exact_id_comparison"]={"common":sorted(old&new),"trivy_only":sorted(old-new),"grype_only":sorted(new-old)}
                bench.write_json(out/f"image-{n}-syft.json",sbom)
                bench.write_json(out/f"image-{n}-grype.json",report)
                rows.append(result)
                print(f"{ref}: Syft packages={result['syft_packages']}; Grype matches={result['matches']}; reported fixes={len(result['reported_fix_matches'])}",flush=True)
            finally:
                archive.unlink(missing_ok=True)
                sbom_path.unlink(missing_ok=True)
        bench.write_json(out/"scanner-comparison.json",{"schema":"appsec.v4-scanner-comparison/v1","images":rows,
            "publication_authorized":False,"limitations":["Different matchers, namespaces, aliases, severity and inventory coverage; counts are not additive.",
             "Reported fixes require vendor and repository verification. No remediation or package removal performed.",
             "Grype DB frozen independently from Trivy DB; exact advisory ID disagreement is not proof of false positive or fix."]})
    print(out/"scanner-comparison.json")


if __name__=="__main__":
    main()
