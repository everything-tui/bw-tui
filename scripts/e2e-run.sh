#!/usr/bin/env bash
# Start Vaultwarden if needed, run integration tests, report results.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SETUP_SCRIPT="${ROOT_DIR}/scripts/e2e-setup.sh"
COMPOSE_FILE="${ROOT_DIR}/docker/compose.yml"
BASE_URL="${VAULTWARDEN_URL:-http://127.0.0.1:8080}"

export VAULTWARDEN_URL="${BASE_URL}"
export E2E_EMAIL="${E2E_EMAIL:-test@example.com}"
export E2E_PASSWORD="${E2E_PASSWORD:-TestPassword123!}"

log() { printf '[e2e-run] %s\n' "$*"; }
die() { printf '[e2e-run] ERROR: %s\n' "$*" >&2; exit 1; }

main() {
  command -v cargo >/dev/null 2>&1 || die "cargo not found; install Rust toolchain"

  log "Ensuring Vaultwarden is up..."
  bash "${SETUP_SCRIPT}"

  log "Running cargo integration tests against ${VAULTWARDEN_URL}..."
  local rc=0
  # Prefer explicit integration test targets when present; fall back to full test suite.
  if cargo test --workspace --tests -- --list 2>/dev/null | grep -qiE 'integration|e2e|vaultwarden'; then
    cargo test --workspace --tests -- --nocapture \
      --test-threads=1 \
      2>&1 | tee /tmp/bitwarden-tui-e2e.log || rc=$?
  else
    log "No named integration/e2e tests found yet; running workspace tests..."
    cargo test --workspace -- --nocapture 2>&1 | tee /tmp/bitwarden-tui-e2e.log || rc=$?
  fi

  echo
  if [[ "${rc}" -eq 0 ]]; then
    log "RESULT: PASS"
    log "Vaultwarden URL: ${VAULTWARDEN_URL}"
    docker compose -f "${COMPOSE_FILE}" ps || true
    exit 0
  else
    log "RESULT: FAIL (exit ${rc})"
    log "Full log: /tmp/bitwarden-tui-e2e.log"
    docker compose -f "${COMPOSE_FILE}" ps || true
    exit "${rc}"
  fi
}

main "$@"
