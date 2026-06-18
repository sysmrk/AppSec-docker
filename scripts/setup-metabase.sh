#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

export METABASE_URL="${METABASE_URL:-http://127.0.0.1:3001}"
export METABASE_ADMIN_EMAIL="${METABASE_ADMIN_EMAIL:-admin@appsec.local}"
export METABASE_ADMIN_PASSWORD="${METABASE_ADMIN_PASSWORD:-AppSec-Metabase-2026!}"
export METABASE_SITE_NAME="${METABASE_SITE_NAME:-AppSec Analytics}"
export METABASE_APPSEC_DB_HOST="${METABASE_APPSEC_DB_HOST:-postgres}"

python3 scripts/setup-metabase.py
