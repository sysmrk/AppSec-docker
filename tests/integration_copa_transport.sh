#!/usr/bin/env bash
set -euo pipefail
name="appsec-copa-export-ci-$$"
source="appsec-local/copa-mirror:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
export BUILDKIT_CONTAINER="$name"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true; docker image rm "$source" appsec-ci/copa-export:test >/dev/null 2>&1 || true' EXIT
docker pull registry:2.8.3
docker pull busybox:1.36
docker tag busybox:1.36 "$source"
docker run -d --privileged --name "$name" -v "$PWD/config/buildkitd.toml:/etc/buildkit/buildkitd.toml:ro" moby/buildkit:v0.29.0
for i in $(seq 1 30); do
  if docker exec "$name" buildctl debug workers >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$name" buildctl debug workers
PYTHONPATH=runner python - <<'PY'
import json, os, subprocess
from appsecctl import copa_transport, patch_sources, scan_evidence
name=os.environ["BUILDKIT_CONTAINER"]
source="appsec-local/copa-mirror:"+"a"*32
identity=scan_evidence.local_image_id(source)
with copa_transport.open_transport(registry_image="registry:2.8.3") as transport:
    ref=transport.stage(source,identity)
    policy=patch_sources.source_policy("docker.io/library/busybox:1.36",{},local_source=ref,pins=transport.pins)
    subprocess.run(["docker","exec","-i",name,"sh","-c","cat >/tmp/policy.json"],input=json.dumps(policy),text=True,check=True)
    subprocess.run(["docker","exec",name,"sh","-ec",
        "mkdir -p /tmp/copa-ci; printf '%s\\n' 'FROM "+ref+"' 'RUN echo patched >/copa-ci-proof' >/tmp/copa-ci/Dockerfile"],check=True)
    # Standalone BuildKit's actual Docker exporter and Docker's actual loader,
    # with the same private registry and source policy as the Copa workflow.
    proc=subprocess.Popen(["docker","exec",name,"buildctl","build","--frontend","dockerfile.v0","--local","context=/tmp/copa-ci","--local","dockerfile=/tmp/copa-ci","--source-policy-file","/tmp/policy.json","--output","type=docker,name=appsec-ci/copa-export:test","--progress","plain"],stdout=subprocess.PIPE)
    loaded=subprocess.run(["docker","load"],stdin=proc.stdout,check=False)
    proc.stdout.close()
    assert proc.wait()==0 and loaded.returncode==0
    assert scan_evidence.local_image_id("appsec-ci/copa-export:test")!=identity
    assert subprocess.check_output(["docker","run","--rm","--network","none","appsec-ci/copa-export:test","cat","/copa-ci-proof"],text=True).strip()=="patched"
assert subprocess.run(["docker","inspect","--type","container","appsec-copa-stage"],capture_output=True).returncode!=0
print("Private staging source, real dedicated BuildKit Docker export, Docker load and cleanup passed")
PY
