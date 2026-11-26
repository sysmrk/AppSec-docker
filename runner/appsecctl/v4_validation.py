"""Bounded, local Nginx smoke check for trusted lab images only."""
from __future__ import annotations
import hashlib
import subprocess
import time
from uuid import uuid4

from . import scan_evidence


def smoke(image, path="/", port=80, *, timeout=25):
    if not path.startswith("/") or path.startswith("//") or any(c.isspace() for c in path) or not 1<=port<=65535:
        raise ValueError("Invalid local HTTP probe")
    if not 1<=timeout<=120:
        raise ValueError("Invalid smoke timeout")
    image_id=scan_evidence.local_image_id(image)
    name="appsec-v4-smoke-"+uuid4().hex
    start=time.monotonic()
    cmd=["docker","run","-d","--name",name,"--label","appsec.managed=v4-lab",
         "--pull=never","--network","none","--no-healthcheck",
         "--security-opt","no-new-privileges:true","--pids-limit","128",
         "--memory","256m","--cpus","1",image_id]
    try:
        subprocess.run(cmd,check=True,capture_output=True,timeout=30)
        while time.monotonic()-start<timeout:
            # Explicit loopback only. No host mounts, socket or published ports.
            # Limit output before hashing; trusted lab workload required.
            r=subprocess.run(["docker","exec",name,"curl","--noproxy","*","--fail","--silent",
                              "--show-error","--max-time","3","--max-filesize","1048576",
                              "--write-out","\n%{http_code}","http://127.0.0.1:"+str(port)+path],
                             capture_output=True,timeout=8)
            if r.returncode==0 and len(r.stdout)<=1048580:
                body,sep,status=r.stdout.rpartition(b"\n")
                if sep and status==b"200":
                    return {"status":"passed","image_id":image_id,"http_status":200,
                            "body_sha256":hashlib.sha256(body).hexdigest(),
                            "seconds":round(time.monotonic()-start,3)}
            time.sleep(0.5)
        return {"status":"failed","image_id":image_id,"reason":"HTTP 200 probe unavailable or failed (curl required)",
                "seconds":round(time.monotonic()-start,3)}
    except (OSError,subprocess.SubprocessError):
        return {"status":"failed","image_id":image_id,"reason":"Container startup or HTTP probe failed"}
    finally:
        subprocess.run(["docker","rm","-f","-v",name],check=False,timeout=30,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


def matches(baseline,candidate):
    return (baseline.get("status")==candidate.get("status")=="passed"
            and baseline.get("http_status")==candidate.get("http_status")==200
            and bool(baseline.get("body_sha256"))
            and baseline["body_sha256"]==candidate.get("body_sha256"))
