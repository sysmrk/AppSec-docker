"""Optional independent Syft/Grype evidence for the V4 local fleet pilot.

Offline scanner containers have no Docker socket. Scanner binaries must be
preloaded by the operator. No implicit pulls, DB updates, or CVE suppression.
"""
from __future__ import annotations

import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
from uuid import uuid4

from . import apt_optimization as apt, scan_evidence

MAX_ARCHIVE=2*1024**3
MAX_JSON=64*1024**2
ID=re.compile(r"sha256:[a-f0-9]{64}")

def enabled():
    return os.getenv("APPSEC_V4_INDEPENDENT_SCAN","false").lower()=="true"

def digest_bytes(data):
    return "sha256:"+hashlib.sha256(data).hexdigest()

def digest_file(path):
    h=hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(1024*1024),b""):
            h.update(block)
    return "sha256:"+h.hexdigest()

def archive_identity(path,expected,inspected=None):
    """Validate the exact single image config in the saved archive.

    A Docker config digest and an OCI manifest digest are different
    identities. Accept a manifest digest only if its actual blob references
    the exact config and the same archive layer paths. Never accept a
    different reported ID merely because the image has a similar tag.
    """
    if not ID.fullmatch(expected):
        raise ValueError("Invalid expected image ID")
    with tarfile.open(path,"r:") as tar:
        members={}
        for m in tar:
            name=m.name.removeprefix("./")
            if name in members:
                raise ValueError("Duplicate archive entry")
            members[name]=m
        def read(name,limit=4*1024**2):
            m=members.get(name)
            if not m or not m.isfile() or m.size>limit:
                raise ValueError("Invalid archive metadata entry")
            return tar.extractfile(m).read()
        rows=json.loads(read("manifest.json"))
        if not isinstance(rows,list) or len(rows)!=1:
            raise ValueError("Expected a single Docker archive image")
        row=rows[0]
        config=read(row["Config"])
        cid=digest_bytes(config)
        cfg=json.loads(config)
        layers=row.get("Layers")
        diffids=(cfg.get("rootfs") or {}).get("diff_ids")
        if not isinstance(layers,list) or not isinstance(diffids,list) or len(layers)!=len(diffids):
            raise ValueError("Archive config/layer count mismatch")
        if any(not ID.fullmatch(d) for d in diffids) or any(not members.get(p) or not members[p].isfile() for p in layers):
            raise ValueError("Invalid archive layer identity")
        linked=set()
        # OCI-format docker save also includes content-addressed manifests.
        # Verify actual manifest bytes and their exact config/layer references.
        for name,m in members.items():
            if not re.fullmatch(r"blobs/sha256/[a-f0-9]{64}",name) or not m.isfile() or m.size>4*1024**2:
                continue
            try:
                raw=read(name)
                if digest_bytes(raw)!="sha256:"+name.rsplit("/",1)[1]:
                    continue
                obj=json.loads(raw)
                if not isinstance(obj,dict) or (obj.get("config") or {}).get("digest")!=cid:
                    continue
                descriptors=obj.get("layers")
                if not isinstance(descriptors,list):
                    continue
                if ["blobs/sha256/"+d["digest"].split(":")[1] for d in descriptors]==layers:
                    linked.add(digest_bytes(raw))
            except (ValueError,TypeError,KeyError,IndexError,AttributeError):
                continue
        method="exact_config_or_linked_manifest"
        if expected!=cid and expected not in linked:
            # With a containerd image store, Docker may identify the
            # manifest/index, while docker save rewrites archive manifests.
            # The daemon export was requested by immutable ID. Require a
            # separate immutable inspect result, explicit digest association,
            # exact ordered diff IDs, platform and full runtime configuration.
            # This is an export binding, not digest equivalence.
            descriptor=(inspected or {}).get("Descriptor") or {}
            repo_digests={d.rsplit("@",1)[-1] for d in (inspected or {}).get("RepoDigests") or []}
            if (not inspected or inspected.get("Id")!=expected or
                    expected not in ({descriptor.get("digest"),descriptor.get("Digest")}|repo_digests) or
                    diffids!=(inspected.get("RootFS") or {}).get("Layers") or
                    cfg.get("os")!=inspected.get("Os") or cfg.get("architecture")!=inspected.get("Architecture") or
                    (cfg.get("variant") or "")!=(inspected.get("Variant") or "")):
                raise ValueError("Saved archive does not match Docker image identity: config="+cid+" expected="+expected)
            runtime=cfg.get("config")
            actual=inspected.get("Config")
            keys=("Entrypoint","Cmd","Env","WorkingDir","User","Volumes","ExposedPorts","Labels","StopSignal","Healthcheck","Shell","OnBuild","ArgsEscaped")
            if not isinstance(runtime,dict) or not isinstance(actual,dict) or any(
                    (runtime.get(k) or None)!=(actual.get(k) or None) for k in keys):
                raise ValueError("Saved archive runtime configuration differs from Docker inspect")
            method="daemon_export_manifest_identity_config_and_layers"
        return {"config_digest":cid,"manifest_digests":sorted(linked),"diff_ids":diffids,"export_binding":method}

def verify_sbom(sbom,identity):
    artifacts=sbom.get("artifacts")
    if not isinstance(artifacts,list) or not artifacts:
        raise ValueError("Independent inventory missing")
    source=sbom.get("source") or {}
    meta=source.get("metadata") or {}
    reported=meta.get("imageID")
    accepted={identity["config_digest"],*identity["manifest_digests"]}
    # Some Syft versions compute an alternate ID. Only accept a mismatch
    # when the original raw config bytes are independently bound to this
    # exact archive. Record the differing reported ID, never rewrite it.
    if reported in accepted:
        method="exact_config_or_linked_manifest"
    else:
        raw=meta.get("config")
        if not isinstance(raw,str):
            raise ValueError("Syft image identity mismatch")
        try:
            verified=digest_bytes(base64.b64decode(raw,validate=True))==identity["config_digest"]
        except (ValueError,TypeError):
            verified=False
        if not verified:
            raise ValueError("Syft image identity mismatch")
        method="exact_raw_config"
    return {"reported_image_id":reported,"identity_method":method}

def db_manifest(root):
    rows={}
    total=0
    for directory,dirs,names in os.walk(root,followlinks=False,onerror=lambda e: (_ for _ in ()).throw(e)):
        for name in sorted(dirs+names):
            p=Path(directory)/name
            if p.is_symlink() or not (p.is_dir() or p.is_file()):
                raise ValueError("Unsupported independent DB cache entry")
            if p.is_file():
                total+=p.stat().st_size
                if total>8*1024**3 or len(rows)>=128:
                    raise ValueError("Independent DB cache exceeds limits")
                rows[p.relative_to(root).as_posix()]=digest_file(p)
    if not any(k.endswith("/vulnerability.db") or k=="vulnerability.db" for k in rows):
        raise ValueError("Grype DB missing")
    return rows

def findings(report):
    matches=report.get("matches")
    if not isinstance(matches,list):
        raise ValueError("Invalid independent vulnerability results")
    if report.get("ignoredMatches"):
        raise ValueError("Independent scanner unexpectedly ignored findings")
    counts=Counter()
    keys=Counter()
    fixes=[]
    for match in matches:
        v,a=match["vulnerability"],match["artifact"]
        if not v.get("id") or not a.get("name") or not a.get("version"):
            raise ValueError("Incomplete independent match")
        counts[str(v.get("severity") or "UNKNOWN").upper()]+=1
        keys[(v["id"],a["name"],a.get("type") or "",v.get("namespace") or "")]+=1
        fix=v.get("fix") or {}
        if fix.get("state")=="fixed" and fix.get("versions"):
            fixes.append({"id":v["id"],"package":a["name"],"installed":a["version"],
                          "type":a.get("type"),"namespace":v.get("namespace"),"fixed_versions":fix["versions"]})
    return {"matches":len(matches),"severity":dict(counts),"reported_fixes":fixes,
            "occurrences":[{"id":k[0],"package":k[1],"type":k[2],"namespace":k[3],"count":n}
                           for k,n in sorted(keys.items())]}

def compare(a,b):
    if not a or not b or a.get("status")!="completed" or b.get("status")!="completed":
        return {"status":"unavailable","message":"Both independent scans must complete"}
    if any(a.get(k)!=b.get(k) for k in ("syft_image_id","grype_image_id","db_files_sha256")):
        return {"status":"not_comparable","message":"Independent scanner or database content changed"}
    if a.get("image_id")==b.get("image_id"):
        return {"status":"not_comparable","message":"Distinct image identities required"}
    if a.get("package_types",{}).keys()!=b.get("package_types",{}).keys():
        return {"status":"not_comparable","message":"Independent inventory types changed"}
    def index(x):
        return Counter({(r["id"],r["package"],r["type"],r["namespace"]):r["count"] for r in x["occurrences"]})
    def rows(x):
        return [{"id":k[0],"package":k[1],"type":k[2],"namespace":k[3],"count":n} for k,n in sorted(x.items())]
    old,new=index(a),index(b)
    return {"status":"observed","before":a["matches"],"after":b["matches"],
            "no_longer_reported":rows(old-new),"introduced":rows(new-old),
            "no_longer_reported_count":sum((old-new).values()),"introduced_count":sum((new-old).values()),
            "message":"Exact match occurrences only; not proof of fix or workload compatibility"}

def scanner(image,args,work_host,db_host=None,env=()):
    name="appsec-independent-"+uuid4().hex
    cmd=["docker","run","--rm","--name",name,"--pull=never","--network=none",
         "--user","0:0","--cap-drop","ALL","--security-opt","no-new-privileges:true",
         "--read-only","--tmpfs","/tmp:rw,nosuid,nodev,mode=1777,size=256m",
         "--memory","2g","--cpus","2","--pids-limit","128",
         "--mount",f"type=bind,src={work_host},dst=/input,readonly"]
    if db_host:
        cmd+=["--mount",f"type=bind,src={db_host},dst=/db,readonly"]
    for value in env:
        cmd+=["-e",value]
    try:
        # Existing bounded job output capture and cancellation boundary.
        raw=apt.run([*cmd,image,*args],600)
        if len(raw.encode())>MAX_JSON:
            raise ValueError("Independent JSON exceeds limit")
        return json.loads(raw)
    finally:
        subprocess.run(["docker","rm","-f",name],check=False,timeout=30,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

def scan(image,report):
    from . import job_watch
    job_watch.emit("independent_scan")
    host=Path(os.environ["APPSEC_SCANNER_WORK_HOST"])
    db_host=Path(os.environ["APPSEC_GRYPE_CACHE_HOST"])
    if not host.is_absolute() or not db_host.is_absolute() or any("," in str(p) for p in (host,db_host)):
        raise ValueError("Invalid scanner mount path")
    root=Path("/scanner-work")
    cache=Path("/grype-cache")
    if not root.is_mount() or not cache.is_mount():
        raise ValueError("Independent scanner mounts missing")
    syft=scan_evidence.local_image_id(os.environ.get("APPSEC_SYFT_IMAGE","anchore/syft:latest"))
    grype=scan_evidence.local_image_id(os.environ.get("APPSEC_GRYPE_IMAGE","anchore/grype:latest"))
    inspect=json.loads(apt.run(["docker","image","inspect",image]))[0]
    if inspect["Id"]!=image or inspect.get("Size",MAX_ARCHIVE)>MAX_ARCHIVE//2:
        raise ValueError("Image exceeds independent scanner pilot limit")
    if shutil.disk_usage(root).free<MAX_ARCHIVE+512*1024**2:
        raise ValueError("Insufficient disk for independent scanner archive")
    hashes=db_manifest(cache)
    with tempfile.TemporaryDirectory(prefix="job-",dir=root) as tmp:
        work=Path(tmp)
        archive=work/"image.tar"
        apt.run(["docker","image","save","--output",str(archive),image],600)
        if archive.stat().st_size>MAX_ARCHIVE:
            raise ValueError("Independent archive exceeds limit")
        identity=archive_identity(archive,image,inspect)
        if identity["diff_ids"]!=(inspect.get("RootFS") or {}).get("Layers"):
            raise ValueError("Saved archive layer inventory differs from Docker inspect")
        archive_hash=digest_file(archive)
        mapped=str(host/work.name)
        sbom=scanner(syft,["scan","docker-archive:/input/image.tar","-o","syft-json"],mapped,
                     env=("SYFT_CHECK_FOR_APP_UPDATE=false","XDG_CACHE_HOME=/tmp/cache","HOME=/tmp"))
        proof=verify_sbom(sbom,identity)
        if digest_file(archive)!=archive_hash:
            raise ValueError("Independent archive changed during scan")
        archive.unlink()
        payload=json.dumps(sbom,ensure_ascii=False,separators=(",",":")).encode()
        (work/"sbom.json").write_bytes(payload)
        env=("GRYPE_DB_CACHE_DIR=/db","GRYPE_DB_AUTO_UPDATE=false","GRYPE_DB_VALIDATE_AGE=true",
             "GRYPE_DB_VALIDATE_BY_HASH_ON_START=true","GRYPE_DB_MAX_ALLOWED_BUILT_AGE=72h",
             "GRYPE_CHECK_FOR_APP_UPDATE=false","HOME=/tmp","XDG_CACHE_HOME=/tmp/cache")
        status=scanner(grype,["db","status","-o","json"],mapped,str(db_host),env)
        result=scanner(grype,["sbom:/input/sbom.json","-o","json"],mapped,str(db_host),env)
        if db_manifest(cache)!=hashes or digest_file(work/"sbom.json")!=digest_bytes(payload):
            raise ValueError("Independent database or SBOM changed")
        summary=findings(result)
        old={v["VulnerabilityID"] for t in report["Results"] for v in t.get("Vulnerabilities") or []}
        new={r["id"] for r in summary["occurrences"]}
        summary.update(status="completed",image_id=image,syft_image_id=syft,grype_image_id=grype,
                       db_files_sha256=hashes,db_status=status,archive_sha256=archive_hash,
                       sbom_sha256=digest_bytes(payload),archive_identity=identity,**proof,
                       package_types=dict(Counter(a.get("type") or "unknown" for a in sbom["artifacts"])),
                       package_count=len(sbom["artifacts"]),
                       exact_id_overlap={"common":len(old&new),"trivy_only":len(old-new),"grype_only":len(new-old)},
                       publication_authorized=False)
        job_watch.emit("independent_complete",summary["matches"])
        return summary,sbom,result
