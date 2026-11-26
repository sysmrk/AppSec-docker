"""Prepare a disposable local Debian source for Copa; never push it."""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

from . import apt_optimization as apt, apt_repository_review as repo, scan_evidence, native_apt

CONFIG_KEYS=native_apt.CONFIG_KEYS
DEFAULT_URL=re.compile(r"https?://(?:deb\.debian\.org|security\.debian\.org)(/debian(?:-security)?)(?=\s|/|$)")


def rewrite(content, mirror):
    main,security=apt.MIRRORS[mirror]
    return DEFAULT_URL.sub(lambda m: security if m[1]=="/debian-security" else main,content)


def cleanup(ref):
    subprocess.run(["docker","image","rm",ref],check=False,timeout=30,
                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


def verify_candidate(original, candidate, *, preparation=False):
    a,b=apt.inspect(original),apt.inspect(candidate)
    layers=a["RootFS"]["Layers"]
    if b["RootFS"]["Layers"][:len(layers)]!=layers or any(a["Config"].get(k)!=b["Config"].get(k) for k in CONFIG_KEYS):
        raise RuntimeError("Copa candidate lineage or runtime configuration changed")
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
                raise RuntimeError("No default Debian source URLs found; refusing unverified mirror preparation")
            apt.run(["docker","commit",cid,ref])
        staged_id=scan_evidence.local_image_id(ref)
        verify_candidate(image,staged_id,preparation=True)
        return {"image_ref":ref,"image_id":staged_id,"mirror":mirror,"availability":selected["counts"]}
    except BaseException:
        cleanup(ref)
        raise
    finally:
        subprocess.run(["docker","rm","-v",cid],check=False,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
