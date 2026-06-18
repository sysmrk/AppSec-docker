#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

failures=0

check() {
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    printf '[OK] %s\n' "${label}"
  else
    printf '[FAIL] %s\n' "${label}"
    failures=$((failures + 1))
  fi
}

port_free() {
  local port="$1"
  ! ss -ltn "( sport = :${port} )" | tail -n +2 | grep -q .
}

check "docker CLI is available" command -v docker
check "docker daemon is reachable" docker info
check "docker-compose is available" command -v docker-compose
check "docker-compose file is valid" docker-compose -f docker-compose.yaml config
check "port 8080 is free or already used by AppSec nginx" bash -lc 'port_free() { ! ss -ltn "( sport = :8080 )" | tail -n +2 | grep -q . || docker ps --format "{{.Names}}" | grep -q "^appsec_nginx_1$"; }; port_free'
check "port 3001 is free or already used by Metabase" bash -lc 'port_free() { ! ss -ltn "( sport = :3001 )" | tail -n +2 | grep -q . || docker ps --format "{{.Names}}" | grep -q "^appsec_metabase_1$"; }; port_free'
check "port 9000 is free or already used by MinIO" bash -lc 'port_free() { ! ss -ltn "( sport = :9000 )" | tail -n +2 | grep -q . || docker ps --format "{{.Names}}" | grep -q "^appsec_minio_1$"; }; port_free'

if [[ ! -f .env ]]; then
  printf '[WARN] .env not found. Start with: cp .env.example .env\n'
fi

if [[ ! -S /var/run/docker.sock ]]; then
  printf '[FAIL] /var/run/docker.sock is missing\n'
  failures=$((failures + 1))
else
  printf '[OK] docker socket exists\n'
fi

if [[ "${failures}" -gt 0 ]]; then
  printf '\nPreflight failed with %s issue(s).\n' "${failures}"
  exit 1
fi

printf '\nPreflight passed.\n'
