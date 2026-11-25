#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

failures=0
warnings=0

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

warn() {
  printf '[WARN] %s\n' "$1"
  warnings=$((warnings + 1))
}

port_free() {
  local port="$1"
  ! ss -ltn "( sport = :${port} )" | tail -n +2 | grep -q .
}

env_value() {
  local key="$1"
  if [[ -f .env ]]; then
    sed -n "s/^${key}=//p" .env | tail -n 1
  else
    sed -n "s/^${key}=//p" .env.example | tail -n 1
  fi
}

check "docker CLI is available" command -v docker
check "docker daemon is reachable" docker info
check "Docker Compose v2 plugin is available" docker compose version
check "Docker Compose file is valid" docker compose -f docker-compose.yaml config
check "port 8080 is free or already used by AppSec nginx" bash -lc 'port_free() { ! ss -ltn "( sport = :8080 )" | tail -n +2 | grep -q . || docker ps --format "{{.Names}}" | grep -Eq "(^|[-_])nginx[-_]1$"; }; port_free'
check "port 3001 is free or already used by Metabase" bash -lc 'port_free() { ! ss -ltn "( sport = :3001 )" | tail -n +2 | grep -q . || docker ps --format "{{.Names}}" | grep -Eq "(^|[-_])metabase[-_]1$"; }; port_free'
check "port 9000 is free or already used by MinIO" bash -lc 'port_free() { ! ss -ltn "( sport = :9000 )" | tail -n +2 | grep -q . || docker ps --format "{{.Names}}" | grep -Eq "(^|[-_])minio[-_]1$"; }; port_free'

if [[ ! -f .env ]]; then
  warn ".env not found. Start with: ./appsec setup"
fi

if [[ ! -S /var/run/docker.sock ]]; then
  printf '[FAIL] /var/run/docker.sock is missing\n'
  failures=$((failures + 1))
else
  printf '[OK] docker socket exists\n'
fi

registry_host="$(env_value REGISTRY_HOST)"
patched_repository="$(env_value PATCHED_REPOSITORY)"
if [[ "${registry_host}" == "localhost:5000" ]]; then
  warn "REGISTRY_HOST still points to localhost:5000. Local Harbor defaults to localhost:8081."
fi
if [[ "${patched_repository}" != */* ]]; then
  warn "PATCHED_REPOSITORY has no project prefix. Harbor usually expects something like library/appsec-patched."
fi

if [[ "${failures}" -gt 0 ]]; then
  printf '\nPreflight failed with %s issue(s).\n' "${failures}"
  exit 1
fi

printf '\nPreflight passed with %s warning(s).\n' "${warnings}"
