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
if [[ -z "${METABASE_ADMIN_PASSWORD:-}" || "${#METABASE_ADMIN_PASSWORD}" -lt 16 ]]; then
  echo "METABASE_ADMIN_PASSWORD must be set to a random value of at least 16 characters in .env" >&2
  exit 1
fi
export METABASE_ADMIN_PASSWORD
export METABASE_SITE_NAME="${METABASE_SITE_NAME:-AppSec Analytics}"
export METABASE_APPSEC_DB_HOST="${METABASE_APPSEC_DB_HOST:-postgres}"

python3 scripts/setup-metabase.py
