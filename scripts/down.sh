#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

remove_volumes=false
remove_harbor=false

usage() {
  cat <<'USAGE'
Usage:
  scripts/down.sh
  scripts/down.sh --volumes
  scripts/down.sh --harbor
  scripts/down.sh --volumes --harbor

Options:
  --volumes   Remove AppSec Docker volumes too. This deletes database/report/cache data.
  --harbor    Also stop the Harbor compose stack created under harbor/runtime/harbor.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --volumes)
      remove_volumes=true
      shift
      ;;
    --harbor)
      remove_harbor=true
      shift
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

compose_args=(-f docker-compose.yaml --profile platform --profile production --profile storage --profile tools --profile maintenance --profile mcp --profile patch down --remove-orphans)
if [[ "${remove_volumes}" == "true" ]]; then
  compose_args+=(-v)
fi

docker compose "${compose_args[@]}"

if [[ "${remove_harbor}" == "true" && -f harbor/runtime/harbor/docker-compose.yml ]]; then
  harbor_args=(-f harbor/runtime/harbor/docker-compose.yml down --remove-orphans)
  if [[ "${remove_volumes}" == "true" ]]; then
    harbor_args+=(-v)
  fi
  docker compose "${harbor_args[@]}"
fi
