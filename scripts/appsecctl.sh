#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"
files=(-f docker-compose.yaml)
if [[ -f docker-compose.override.yaml ]]; then files+=(-f docker-compose.override.yaml); fi
docker compose "${files[@]}" --profile tools run --rm appsec-runner "$@"
