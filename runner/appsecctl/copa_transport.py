"""Short-lived Docker-to-dedicated-BuildKit source transport.

Only the local Docker daemon can push through the loopback host port. The
registry network contains the registry, BuildKit and current worker only.
No final patched image is uploaded here or to an external registry.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
import re
import subprocess
import time
from uuid import uuid4

from . import db, image_sources, scan_evidence, apt_optimization as apt, job_watch

STAGE_HOST="appsec-copa-stage:5000"
STAGE_NAME="appsec-copa-stage"
STAGE_REF=re.compile(r"appsec-copa-stage:5000/appsec-local/copa-mirror:[a-f0-9]{32}")
DIGEST=re.compile(r"sha256:[a-f0-9]{64}")


def quiet(*args):
    try:
        subprocess.run(["docker",*args],check=False,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    except (OSError,subprocess.SubprocessError):
        print("COPA_STAGE_CLEANUP_FAILED action="+args[0],flush=True)


class Transport:
    def __init__(self,port):
        self.port=port
        self.pins={}
        self.aliases=[]

    def stage(self,ref,expected):
        if not re.fullmatch(r"appsec-local/copa-mirror:[a-f0-9]{32}",ref):
            raise ValueError("Unexpected local preparation reference")
        if scan_evidence.local_image_id(ref)!=expected or not DIGEST.fullmatch(expected):
            raise RuntimeError("SCAN_EVIDENCE_INVALID: Staging image identity mismatch")
        external="127.0.0.1:"+str(self.port)+"/"+ref
        internal=STAGE_HOST+"/"+ref
        self.aliases.extend([external,internal])
        apt.run(["docker","tag",expected,external])
        # docker push reports the manifest digest; the exact digest is then
        # independently pulled and matched to the original config ID.
        output=apt.run(["docker","push",external],300)
        matches=re.findall(r"\bdigest:\s*(sha256:[a-f0-9]{64})\b",output)
        if len(set(matches))!=1:
            raise RuntimeError("SCAN_EVIDENCE_INVALID: Staged manifest digest unavailable")
        digest=matches[0]
        pinned=external.rsplit(":",1)[0]+"@"+digest
        self.aliases.append(pinned)
        apt.run(["docker","pull",pinned],300)
        if scan_evidence.local_image_id(pinned)!=expected:
            raise RuntimeError("SCAN_EVIDENCE_INVALID: Staged manifest does not match prepared image")
        # Copa's client-side local image inspection can now use its internal
        # reference without trying to fetch a registry outside the daemon.
        apt.run(["docker","tag",expected,internal])
        self.pins[internal]=digest
        job_watch.emit("copa_stage_ready")
        return internal

    def cleanup(self):
        for ref in reversed(self.aliases):
            quiet("image","rm",ref)


@contextmanager
def open_transport(*, registry_image=None):
    """Create one private bridge and a loopback-only host publishing port."""
    buildkit=os.getenv("BUILDKIT_CONTAINER","appsec-buildkit")
    if not registry_image:
        with db.connect() as conn:
            sources=image_sources.configured_sources(conn)
        if not sources:
            raise RuntimeError("PATCH_SOURCE_POLICY: Configure approved registry image sources first")
        registry_image=image_sources.pull_ordered(image_sources.ordered_candidates(
            sources,[os.getenv("APPSEC_COPA_STAGE_REGISTRY_IMAGE","docker.io/library/registry:2.8.3")]))
    registry_id=scan_evidence.local_image_id(registry_image)
    network="appsec-copa-stage-"+uuid4().hex
    net_created=False
    container=None
    connected=[]
    transport=None
    job_watch.emit("copa_stage")
    try:
        apt.run(["docker","network","create","--driver","bridge","--label","appsec.managed=copa-stage",network])
        net_created=True
        # Fixed name prevents two jobs from sharing the staging DNS alias.
        # Never remove a pre-existing container owned by another invocation.
        container=apt.run(["docker","run","-d","--pull=never","--name",STAGE_NAME,
                           "--label","appsec.managed=copa-stage","--network",network,
                           "--network-alias","appsec-copa-stage",
                           "--publish","127.0.0.1::5000","--security-opt","no-new-privileges:true",
                           "--cap-drop","ALL","--pids-limit","128",registry_id]).strip()
        if not re.fullmatch(r"[a-f0-9]{64}",container):
            raise RuntimeError("Invalid staging registry container ID")
        apt.run(["docker","network","connect",network,buildkit])
        connected.append(buildkit)
        # The worker may inspect manifest annotations through the private DNS
        # endpoint. On the CI host HOSTNAME is not a Docker container.
        hostname=os.getenv("HOSTNAME","")
        if re.fullmatch(r"[a-f0-9]{12,64}",hostname):
            check=subprocess.run(["docker","inspect","--type","container","--format","{{.Id}}",hostname],
                                 capture_output=True,text=True,timeout=15)
            if check.returncode==0 and re.fullmatch(r"[a-f0-9]{64}",check.stdout.strip()):
                worker=check.stdout.strip()
                apt.run(["docker","network","connect",network,worker])
                connected.append(worker)
        bound=apt.run(["docker","port",container,"5000/tcp"]).strip()
        match=re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})",bound)
        if not match or not 1<=int(match[1])<=65535:
            raise RuntimeError("Staging registry is not bound exclusively to loopback")
        for _ in range(20):
            job_watch.checkpoint()
            ready=subprocess.run(["docker","exec",container,"wget","-q","-O","/dev/null","http://127.0.0.1:5000/v2/"],
                                 capture_output=True,timeout=5)
            if ready.returncode==0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("Temporary staging registry did not become ready")
        transport=Transport(int(match[1]))
        yield transport
    finally:
        if transport:
            transport.cleanup()
        if container and re.fullmatch(r"[a-f0-9]{64}",container):
            quiet("rm","-f","-v",container)
        for member in reversed(connected):
            quiet("network","disconnect",network,member)
        if net_created:
            quiet("network","rm",network)
