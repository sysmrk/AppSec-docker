#!/usr/bin/env bash
set -euo pipefail

docker-compose -f docker-compose.yaml run --rm appsec-runner "$@"
