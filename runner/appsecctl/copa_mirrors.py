"""Prepare a disposable local Debian source for Copa; never push it."""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

from . import apt_optimization as apt, apt_repository_review as repo, scan_evidence, native_apt, image_sources

CONFIG_KEYS=native_apt.CONFIG_KEYS
DEFAULT_URL=re.compile(r"https?://(?:deb\.debian\.org|security\.debian\.org)(/debian(?:-security)?)(?=\s|/|$)")


def rewrite(content, mirror):
    main,security=apt.MIRRORS[mirror]
    return DEFAULT_URL.sub(lambda m: security if m[1]=="/debian-security" else main,content)


def cleanup(ref):
    subprocess.run(["docker","image","rm",ref],check=False,timeout=30,
                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


def verify_candidate(original, candidate, *, preparation=False, source_ref=None):
    a,b=apt.inspect(original),apt.inspect(candidate)
    layers=a["RootFS"]["Layers"]
    if b["RootFS"]["Layers"][:len(layers)]!=layers or any(a["Config"].get(k)!=b["Config"].get(k) for k in CONFIG_KEYS if k!="Labels"):
        raise RuntimeError("Copa candidate lineage or runtime configuration changed")
    labels_a=dict(a["Config"].get("Labels") or {})
    labels_b=dict(b["Config"].get("Labels") or {})
    if not preparation and source_ref and "BaseImage" not in labels_a:
        generated=labels_b.pop("BaseImage",None)
        if generated and image_sources.canonical_ref(generated)!=image_sources.canonical_ref(source_ref):
            raise RuntimeError("Unexpected Copa BaseImage label")
    if labels_a!=labels_b:
        raise RuntimeError("Copa changed application image labels")
    old,new=apt.inventory(original),apt.inventory(candidate)
    if preparation and old!=new:
        raise RuntimeError("Mirror preparation changed package inventory")
    if not preparation:
        if old==new:
            raise RuntimeError("Copa did not change any installed package; no verified patch")
        if not set(old)<=set(new):
            raise RuntimeError("Copa removed installed packages unexpectedly")
        for name in old:
            if old[name]["version"]!=new[name]["version"]:
                apt.container(candidate,'dpkg --compare-versions "$1" lt "$2"',[old[name]["version"],new[name]["version"]])


def prepare(image,report,mirrors):
    apt.inspect(image)
    info=report.get("Metadata",{}).get("OS") or {}
    if info.get("Family")!="debian" or str(info.get("Name","")).split(".")[0] not in ("12","13"):
        raise RuntimeError("Package mirror preparation supports Debian 12/13 only")
    selected=repo.availability(image,mirrors)
    if selected["status"]!="repository_checked":
        raise RuntimeError("All approved Debian package mirrors are unavailable")
    mirror=selected["mirror"]
    result=prepare_sources(image,mirror)
    result["availability"]=selected["counts"]
    return result


def prepare_sources(image, mirror):
    base=apt.inspect(image)
    if (base["Config"].get("Labels") or {}).get("BaseImage"):
        raise RuntimeError("Previously Copa-patched input requires separate lineage review")
    ref="appsec-local/copa-mirror:"+uuid4().hex
    cid=apt.run(["docker","create","--pull=never","--network","none",image]).strip()
    if not re.fullmatch(r"[a-f0-9]{64}",cid):
        raise RuntimeError("Invalid local preparation container ID")
    try:
        with tempfile.TemporaryDirectory(prefix="appsec-copa-mirror-") as tmp:
            root=Path(tmp)
            paths=[]
            # Only known APT sources under /etc/apt; no arbitrary path input.
            for remote,local in [("/etc/apt/sources.list",root/"sources.list"),("/etc/apt/sources.list.d",root/"sources.list.d")]:
                result=subprocess.run(["docker","cp",cid+":"+remote,str(local)],capture_output=True,text=True,timeout=30)
                if result.returncode:
                    if "could not find" not in result.stderr.lower() and "no such file" not in result.stderr.lower():
                        raise RuntimeError("Cannot read APT sources from local image")
                    continue
                if local.is_dir() and not local.is_symlink():
                    paths.extend((remote+"/"+x.name,x) for x in local.iterdir() if x.suffix in (".list",".sources"))
                else:
                    paths.append((remote,local))
            changed=0
            for remote,local in paths:
                if local.is_symlink() or not local.is_file() or local.stat().st_size>1024*1024:
                    raise RuntimeError("Unexpected APT source file")
                content=local.read_text()
                updated=rewrite(content,mirror)
                if updated!=content:
                    local.write_text(updated)
                    apt.run(["docker","cp",str(local),cid+":"+remote])
                    changed+=1
            if not changed:
                main,security=apt.MIRRORS[mirror]
                contents="\n".join(local.read_text() for _,local in paths)
                if main not in contents or security not in contents:
                    raise RuntimeError("No default Debian source URLs found; refusing unverified mirror preparation")
            config=root/"99-appsec-repository-check"
            config.write_text('APT::Update::Error-Mode "any";\nAcquire::Check-Valid-Until "true";\nAcquire::AllowInsecureRepositories "false";\nAPT::Get::AllowUnauthenticated "false";\nAcquire::https::Verify-Peer "true";\nAcquire::https::Verify-Host "true";\nAcquire::Retries "1";\nAcquire::https::Timeout "30";\nAcquire::http::Timeout "30";\n')
            apt.run(["docker","cp",str(config),cid+":/etc/apt/apt.conf.d/99-appsec-repository-check"])
            apt.run(["docker","commit",cid,ref])
        staged_id=scan_evidence.local_image_id(ref)
        verify_candidate(image,staged_id,preparation=True)
        return {"image_ref":ref,"image_id":staged_id,"mirror":mirror}
    except BaseException:
        cleanup(ref)
        raise
    finally:
        subprocess.run(["docker","rm","-v",cid],check=False,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
