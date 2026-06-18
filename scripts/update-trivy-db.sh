#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -f "${ROOT_DIR}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "${ROOT_DIR}/.env"
  set +a
fi

TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:latest}"
TRIVY_DB_REPOSITORY="${TRIVY_DB_REPOSITORY:-ghcr.io/aquasecurity/trivy-db:2}"
TRIVY_CACHE_VOLUME="${TRIVY_CACHE_VOLUME:-appsec_trivy_cache}"
INTERVAL_SECONDS="${TRIVY_DB_UPDATE_INTERVAL_SECONDS:-21600}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/update-trivy-db.sh
  scripts/update-trivy-db.sh --once
  scripts/update-trivy-db.sh --watch
  scripts/update-trivy-db.sh --interval-seconds 3600 --watch

Environment:
  TRIVY_IMAGE
  TRIVY_DB_REPOSITORY
  TRIVY_CACHE_VOLUME
  TRIVY_DB_UPDATE_INTERVAL_SECONDS
USAGE
}

update_once() {
  docker volume create "${TRIVY_CACHE_VOLUME}" >/dev/null
  docker run --rm \
    -e "TRIVY_DB_REPOSITORY=${TRIVY_DB_REPOSITORY}" \
    -v "${TRIVY_CACHE_VOLUME}:/root/.cache/trivy" \
    "${TRIVY_IMAGE}" image --download-db-only
}

mode="once"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --once)
      mode="once"
      shift
      ;;
    --watch)
      mode="watch"
      shift
      ;;
    --interval-seconds)
      INTERVAL_SECONDS="${2:?missing interval value}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "${mode}" == "once" ]]; then
  update_once
  exit 0
fi

while true; do
  update_once
  sleep "${INTERVAL_SECONDS}"
done
