#!/usr/bin/env bash
set -euo pipefail

docker compose -f docker-compose.yaml --profile tools run --rm appsec-runner "$@"
