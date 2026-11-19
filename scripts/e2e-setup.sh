#!/usr/bin/env bash
# Wait for local Vaultwarden to become healthy and prepare E2E credentials.
#
# Registration against Vaultwarden requires client-side crypto
# (POST /api/accounts/register with masterPasswordHash, encrypted user key,
# and RSA keypair). That is done by the Rust integration tests, not from shell.
# This script only ensures the server is reachable.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/docker/compose.yml"
BASE_URL="${VAULTWARDEN_URL:-http://127.0.0.1:8080}"
ALIVE_URL="${BASE_URL}/alive"
MAX_WAIT_SECONDS="${E2E_MAX_WAIT:-90}"

# Canonical test account (used by integration tests after crypto register).
export E2E_EMAIL="${E2E_EMAIL:-test@example.com}"
export E2E_PASSWORD="${E2E_PASSWORD:-TestPassword123!}"

log() { printf '[e2e-setup] %s\n' "$*"; }
die() { printf '[e2e-setup] ERROR: %s\n' "$*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

start_compose_if_needed() {
  require_cmd docker
  if ! docker info >/dev/null 2>&1; then
    die "Docker daemon is not running. Start Docker Desktop (or dockerd) and retry."
  fi

  local status
  status="$(docker compose -f "${COMPOSE_FILE}" ps --status running -q 2>/dev/null || true)"
  if [[ -z "${status}" ]]; then
    log "Starting Vaultwarden via docker compose..."
    docker compose -f "${COMPOSE_FILE}" up -d
  else
    log "Vaultwarden compose service already running."
  fi
}

wait_for_alive() {
  require_cmd curl
  local elapsed=0
  log "Waiting for ${ALIVE_URL} (timeout ${MAX_WAIT_SECONDS}s)..."
  while (( elapsed < MAX_WAIT_SECONDS )); do
    if curl -fsS --max-time 2 "${ALIVE_URL}" >/dev/null 2>&1; then
      log "Vaultwarden is ready at ${BASE_URL}"
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  die "Vaultwarden did not become ready within ${MAX_WAIT_SECONDS}s (${ALIVE_URL})"
}

check_health_status() {
  local health
  health="$(docker compose -f "${COMPOSE_FILE}" ps --format '{{.Health}}' 2>/dev/null | head -n1 || true)"
  if [[ -n "${health}" ]]; then
    log "Compose health status: ${health}"
  fi
}

# Optional: probe register endpoint shape. Full registration needs crypto.
# Documented endpoint: POST ${BASE_URL}/api/accounts/register
# Body (camelCase JSON): email, masterPasswordHash, key, kdf, kdfIterations, keys{publicKey,encryptedPrivateKey}
probe_register_endpoint_docs() {
  log "Test credentials (for Rust integration register/login):"
  log "  email=${E2E_EMAIL}"
  log "  password=${E2E_PASSWORD}"
  log "Register endpoint: POST ${BASE_URL}/api/accounts/register"
  log "Shell registration skipped — requires encrypted keys; Rust tests perform register."
}

main() {
  start_compose_if_needed
  wait_for_alive
  check_health_status
  probe_register_endpoint_docs
  log "Setup complete. URL=${BASE_URL}"
}

main "$@"
