#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARBOR_DIR="${ROOT_DIR}/harbor"
RUNTIME_DIR="${HARBOR_DIR}/runtime"
INSTALLER_DIR="${RUNTIME_DIR}/harbor"
VERSION="${HARBOR_VERSION:-latest}"
HOSTNAME="${HARBOR_HOSTNAME:-localhost}"
HTTP_PORT="${HARBOR_HTTP_PORT:-8081}"
ADMIN_PASSWORD="${HARBOR_ADMIN_PASSWORD:-}"
DB_PASSWORD="${HARBOR_DB_PASSWORD:-}"
DATA_VOLUME="${HARBOR_DATA_VOLUME:-${HARBOR_DIR}/data}"
LOG_DIR="${HARBOR_LOG_DIR:-${HARBOR_DIR}/logs}"

usage() {
  cat <<'EOF'
Usage: scripts/harbor.sh <command>

Commands:
  install   Download the official Harbor online installer and generate harbor.yml
  up        Start Harbor using the official generated Docker Compose stack
  down      Stop Harbor
  login     docker login to the local Harbor endpoint
  status    Show Harbor containers
  url       Print Harbor UI and registry endpoints

Environment:
  HARBOR_VERSION=latest|v2.x.y
  HARBOR_HOSTNAME=localhost
  HARBOR_HTTP_PORT=8081
  HARBOR_ADMIN_PASSWORD=strong-random-password
  HARBOR_DB_PASSWORD=strong-random-password
EOF
}

latest_version() {
  curl -fsSL https://api.github.com/repos/goharbor/harbor/releases/latest \
    | sed -n 's/.*"tag_name": "\(v[^"]*\)".*/\1/p' \
    | head -n 1
}

resolved_version() {
  if [[ "${VERSION}" == "latest" ]]; then
    latest_version
  else
    printf '%s\n' "${VERSION}"
  fi
}

compose_cmd() {
  if command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    docker compose "$@"
  fi
}

run_as_root_on_runtime() {
  mkdir -p "${RUNTIME_DIR}"
  docker run --rm -v "${RUNTIME_DIR}:/runtime" alpine:3.20 sh -c "$1"
}

clean_installer_dir() {
  run_as_root_on_runtime "rm -rf /runtime/harbor"
}

fix_installer_permissions() {
  run_as_root_on_runtime "chown -R $(id -u):$(id -g) /runtime/harbor && chmod -R u+rwX,go+rX /runtime/harbor"
}

bind_harbor_to_localhost() {
  sed -i "s|- ${HTTP_PORT}:8080|- 127.0.0.1:${HTTP_PORT}:8080|g" "${INSTALLER_DIR}/docker-compose.yml"
}

render_config() {
  mkdir -p "${HARBOR_DIR}" "${DATA_VOLUME}" "${LOG_DIR}"
  sed \
    -e "s|\${HARBOR_HOSTNAME}|${HOSTNAME}|g" \
    -e "s|\${HARBOR_HTTP_PORT}|${HTTP_PORT}|g" \
    -e "s|\${HARBOR_ADMIN_PASSWORD}|${ADMIN_PASSWORD}|g" \
    -e "s|\${HARBOR_DB_PASSWORD}|${DB_PASSWORD}|g" \
    -e "s|\${HARBOR_DATA_VOLUME}|${DATA_VOLUME}|g" \
    -e "s|\${HARBOR_LOG_DIR}|${LOG_DIR}|g" \
    "${HARBOR_DIR}/harbor.yml.tmpl" > "${INSTALLER_DIR}/harbor.yml"
}

require_harbor_passwords() {
  if [[ -z "${ADMIN_PASSWORD}" || -z "${DB_PASSWORD}" || "${#ADMIN_PASSWORD}" -lt 16 || "${#DB_PASSWORD}" -lt 16 ]]; then
    echo "Set HARBOR_ADMIN_PASSWORD and HARBOR_DB_PASSWORD to distinct random values of at least 16 characters." >&2
    exit 1
  fi
}

install_harbor() {
  require_harbor_passwords
  local version archive url
  version="$(resolved_version)"
  if [[ -z "${version}" ]]; then
    echo "could not resolve Harbor version" >&2
    exit 1
  fi
  archive="${RUNTIME_DIR}/harbor-online-installer-${version}.tgz"
  url="https://github.com/goharbor/harbor/releases/download/${version}/harbor-online-installer-${version}.tgz"

  mkdir -p "${RUNTIME_DIR}"
  if [[ ! -f "${archive}" ]]; then
    curl -fL --retry 5 --retry-all-errors -o "${archive}" "${url}"
  fi
  clean_installer_dir
  tar -xzf "${archive}" -C "${RUNTIME_DIR}"
  render_config
  (cd "${INSTALLER_DIR}" && ./prepare --with-trivy)
  fix_installer_permissions
  bind_harbor_to_localhost
  (cd "${INSTALLER_DIR}" && compose_cmd down || true)
  (cd "${INSTALLER_DIR}" && compose_cmd up -d)
  echo "Harbor is ready at http://${HOSTNAME}:${HTTP_PORT}"
}

case "${1:-}" in
  install)
    install_harbor
    ;;
  up)
    (cd "${INSTALLER_DIR}" && compose_cmd up -d)
    ;;
  down)
    (cd "${INSTALLER_DIR}" && compose_cmd down)
    ;;
  login)
    require_harbor_passwords
    printf '%s' "${ADMIN_PASSWORD}" | docker login "${HOSTNAME}:${HTTP_PORT}" -u admin --password-stdin
    ;;
  status)
    (cd "${INSTALLER_DIR}" && compose_cmd ps)
    ;;
  url)
    echo "UI:       http://${HOSTNAME}:${HTTP_PORT}"
    echo "Registry: ${HOSTNAME}:${HTTP_PORT}/library"
    ;;
  *)
    usage
    exit 2
    ;;
esac
