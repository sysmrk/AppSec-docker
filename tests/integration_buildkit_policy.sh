#!/usr/bin/env bash
# Exercise the actual BuildKit policy engine, not a Python imitation.
set -euo pipefail
name="appsec-policy-ci-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker run -d --privileged --name "$name" moby/buildkit:v0.29.0
for i in $(seq 1 30); do
  if docker exec "$name" buildctl debug workers >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$name" buildctl debug workers
# The invalid source hostname must never be resolved over the network.
PYTHONPATH=runner python - <<'PY' | docker exec -i "$name" sh -c 'cat >/tmp/policy.json'
import json
from appsecctl.patch_sources import source_policy
print(json.dumps(source_policy(
    "docker.io/library/busybox:1.36",
    {"source.invalid/library/debian:stable-slim": "docker.io/library/busybox:1.36",
     "docker.io/library/debian:stable-slim": "docker.io/library/busybox:1.36"}
)))
PY
docker exec "$name" sh -eu -c '
mkdir -p /tmp/policy-test
printf "%s\n" "FROM source.invalid/library/debian:stable-slim" "RUN busybox true" >/tmp/policy-test/Dockerfile
buildctl build --frontend dockerfile.v0 --local context=/tmp/policy-test --local dockerfile=/tmp/policy-test --source-policy-file /tmp/policy.json --progress plain
printf "%s\n" "FROM docker.io/library/debian:stable-slim" "RUN busybox true" >/tmp/policy-test/Dockerfile
buildctl build --frontend dockerfile.v0 --local context=/tmp/policy-test --local dockerfile=/tmp/policy-test --source-policy-file /tmp/policy.json --progress plain
for ref in source.invalid/library/debian:stable-slim-extra sourceXinvalid/library/debian:stable-slim docker.io/library/alpine:latest; do
  printf "FROM %s\n" "$ref" >/tmp/policy-test/Dockerfile
  if buildctl build --frontend dockerfile.v0 --local context=/tmp/policy-test --local dockerfile=/tmp/policy-test --source-policy-file /tmp/policy.json --progress plain >/tmp/denied.log 2>&1; then
    echo "ERROR: unexpected source accepted: $ref" >&2
    exit 1
  fi
  cat /tmp/denied.log
  grep -F "source denied by policy" /tmp/denied.log
done
'
