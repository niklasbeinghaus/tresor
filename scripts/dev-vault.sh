#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)
PID_FILE="${ROOT_DIR}/.vault-dev.pid"
LOG_FILE="${ROOT_DIR}/.vault-dev.log"
VAULT_ADDR="http://127.0.0.1:8200"
VAULT_TOKEN="root"

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf '%s\n' "missing required command: $1" >&2
    exit 1
  }
}

running_pid() {
  [[ -f "${PID_FILE}" ]] || return 1
  local pid
  pid=$(<"${PID_FILE}")
  [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1
}

stop_server() {
  if running_pid; then
    local pid
    pid=$(<"${PID_FILE}")
    kill "${pid}"
    rm -f "${PID_FILE}"
    printf '%s\n' "Vault dev server stopped"
  else
    rm -f "${PID_FILE}"
    printf '%s\n' "Vault dev server is not running"
  fi
}

wait_for_health() {
  local attempts=0
  until curl -sf "${VAULT_ADDR}/v1/sys/health" >/dev/null; do
    attempts=$((attempts + 1))
    if [[ "${attempts}" -ge 30 ]]; then
      printf '%s\n' "Vault dev server did not become healthy within 15s" >&2
      exit 1
    fi
    sleep 0.5
  done
}

if [[ "${1:-}" == "stop" ]]; then
  stop_server
  exit 0
fi

require_command vault
require_command curl

if running_pid; then
  printf '%s\n' "Vault dev server already running: ${VAULT_ADDR} (token: ${VAULT_TOKEN})"
  exit 0
fi

vault server -dev -dev-root-token-id="${VAULT_TOKEN}" -dev-listen-address=127.0.0.1:8200 >"${LOG_FILE}" 2>&1 &
printf '%s\n' "$!" >"${PID_FILE}"

wait_for_health
VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_TOKEN}" "${SCRIPT_DIR}/seed-vault.sh"
printf '%s\n' "Vault dev server ready: ${VAULT_ADDR} (token: ${VAULT_TOKEN})"
