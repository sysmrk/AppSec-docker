#!/usr/bin/env bash
set -euo pipefail
name="appsec-copa-export-ci-$$"
source="appsec-local/copa-mirror:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
export BUILDKIT_CONTAINER="$name"
trap 'docker rm -f "$name" "$name-owner" >/dev/null 2>&1 || true; docker image rm "$source" appsec-ci/copa-export:test >/dev/null 2>&1 || true' EXIT
docker pull registry:2.8.3
docker pull busybox:1.36
docker pull debian:13-slim
# Prepare the actual Debian helper using the same CA bootstrap as the worker.
PYTHONPATH=runner python - <<'PYHELPER'
from appsecctl import copa_mirrors,scan_evidence,apt_optimization as apt
image=scan_evidence.local_image_id("debian:13-slim")
helper=copa_mirrors.prepare_sources(image,"debian",helper=True)
try:
    print(apt.container(helper["image_id"],'test -s /etc/ssl/certs/ca-certificates.crt || test -s /etc/apt/appsec-helper-ca.pem; apt-config dump | grep -E "Verify-Peer|Verify-Host|AllowUnauthenticated|Check-Valid-Until"'))
    assert apt.inventory(image)==apt.inventory(helper["image_id"])
finally:
    copa_mirrors.cleanup(helper["image_ref"])
PYHELPER
# Exercise the same docker commit preparation as the production path.
# A multi-platform index ID is not a single-platform image config ID.
cid=$(docker create --platform linux/amd64 busybox:1.36)
docker commit "$cid" "$source"
docker rm -v "$cid"
# Real bridge, host, and shared namespace executors. Exercise the same
# transport and docker exporter for each network layout.
for mode in bridge host shared; do
export APPSEC_TEST_NETWORK_MODE="$mode"
if [ "$mode" = shared ]; then
  docker run -d --name "$name-owner" busybox:1.36 sleep 600
  net="container:$name-owner"
else
  net="$mode"
fi
docker run -d --privileged --network "$net" --name "$name" -v "$PWD/config/buildkitd.toml:/etc/buildkit/buildkitd.toml:ro" moby/buildkit:v0.29.0
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
    assert ref.startswith("127.0.0.1:15000/" if os.environ["APPSEC_TEST_NETWORK_MODE"]=="host" else "appsec-copa-stage:5000/")
    alias="source.invalid/library/helper:1"
    policy=patch_sources.source_policy("docker.io/library/busybox:1.36",{alias:ref},local_source=ref,pins=transport.pins)
    subprocess.run(["docker","exec","-i",name,"sh","-c","cat >/tmp/policy.json"],input=json.dumps(policy),text=True,check=True)
    subprocess.run(["docker","exec",name,"sh","-ec",
        "mkdir -p /tmp/copa-ci; printf '%s\\n' 'FROM "+alias+" AS helper' 'FROM "+ref+"' 'COPY --from=helper /bin/busybox /tmp/helper-busybox' 'RUN echo patched >/copa-ci-proof' >/tmp/copa-ci/Dockerfile"],check=True)
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

docker rm -f "$name"
if [ "$mode" = shared ]; then docker rm -f "$name-owner"; fi
docker image rm appsec-ci/copa-export:test
done
