#!/usr/bin/env bash
# launcher.sh — keep Ganache and Ghost_Comm running until manually stopped.
# Hardened for ParrotOS / Debian systems with Tor.

set -Eeuo pipefail
IFS=$'\n\t'

# --- Environment ---
export PGP_PASSPHRASE="111318"
PORT=${PORT:-7545}
LOG=/tmp/ganache.log
GANACHE_LOG=${GANACHE_LOG:-/tmp/ganache.log}
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BLOCKCHAIN_UTILS="${PROJECT_ROOT}/blockchain_utils.py"
C2_ENTRY="${PROJECT_ROOT}/main.py"
RESTART_DELAY=${RESTART_DELAY:-5}
running=true
GANACHE_PID=""
C2_PID=""

# --- Color Codes ---
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'

# --- Logging ---
log()   { printf "[%s%s%s] %s\n" "$1" "$2" "$C_RESET" "$3"; }
info()  { log "$C_BLUE" "i" "$1"; }
success(){ log "$C_GREEN" "+" "$1"; }
warn()  { log "$C_YELLOW" "!" "$1"; }
error() { log "$C_RED" "x" "$1"; }

# --- Error trap ---
trap 'error "Unexpected failure on line $LINENO"; exit 1' ERR

# --- Safe cleanup of PIDs ---
kill_pid() {
  local pid="$1"
  [[ -z "$pid" ]] && return 0
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}

# --- Kill any process on port (Ganache cleanup) ---
kill_port_processes() {
  if lsof -i :$PORT >/dev/null 2>&1; then
    warn "Port $PORT in use. Killing old process..."
    PID=$(lsof -ti :$PORT)
    sudo kill -9 $PID || true
    sleep 1
  fi
}

# --- Tor startup (resilient) ---
restart_tor() {
  info "Restarting Tor cleanly..."
  sudo pkill -9 tor 2>/dev/null || true
  sudo systemctl stop tor@default.service tor.service 2>/dev/null || true
  sudo rm -rf /run/tor /var/lib/tor/lock 2>/dev/null || true
  sudo mkdir -p /run/tor && sudo chown debian-tor:debian-tor /run/tor

  if sudo systemctl start tor@default.service; then
    success "Tor started successfully."
  else
    warn "Tor failed to start normally. Attempting direct run..."
    sudo -u debian-tor tor -f /etc/tor/torrc || error "Tor manual start failed; check torrc."
  fi
}

# --- Start Ganache ---
start_ganache() {
  info "Starting Ganache on port $PORT..."
  nohup ganache --wallet.deterministic --port "$PORT" >"$LOG" 2>&1 &
  GANACHE_PID=$!
  for i in {1..10}; do
    if curl -s "http://127.0.0.1:$PORT" > /dev/null; then
      success "Ganache is live (PID $GANACHE_PID)."
      return 0
    fi
    sleep 1
  done
  error "Ganache failed to respond on port $PORT."
  return 1
}

# --- Blockchain utils ---
run_blockchain_utils() {
  if [[ ! -f "$BLOCKCHAIN_UTILS" ]]; then
    error "Missing blockchain utils at ${BLOCKCHAIN_UTILS}."
    return 1
  fi
  info "Launching blockchain utils..."
  if ! python3 "$BLOCKCHAIN_UTILS"; then
    error "blockchain_utils.py exited abnormally; continuing."
  fi
}

# --- Verify Ganache alive ---
ensure_ganache_ready() {
  if [[ -n "$GANACHE_PID" ]] && kill -0 "$GANACHE_PID" 2>/dev/null; then
    if curl -sf "http://127.0.0.1:${PORT}" >/dev/null 2>&1; then
      return 0
    fi
    warn "Ganache (PID ${GANACHE_PID}) unresponsive; restarting..."
    kill_pid "$GANACHE_PID"
    GANACHE_PID=""
  fi

  kill_port_processes
  if start_ganache; then
    run_blockchain_utils
    return 0
  fi
  return 1
}

# --- Launch Ghost_Comm ---
launch_c2() {
  if [[ ! -f "$C2_ENTRY" ]]; then
    error "Ghost_Comm entrypoint missing at ${C2_ENTRY}."
    return 127
  fi

  info "Launching Ghost_Comm..."
  python3 "$C2_ENTRY" ghost_comm &
  C2_PID=$!
  wait "$C2_PID"
  local exit_code=$?
  C2_PID=""
  return "$exit_code"
}

# --- Cleanup ---
cleanup() {
  local exit_code=${1:-0}
  $running || exit "$exit_code"
  running=false
  echo
  info "Shutting down launcher..."
  kill_pid "$C2_PID"
  kill_pid "$GANACHE_PID"
  exit "$exit_code"
}

trap 'cleanup 0' INT TERM
trap 'cleanup 0' TSTP

# --- Main Loop ---
info "Launcher online. Press Ctrl+C to stop."
restart_tor

attempt=1
while $running; do
  while $running; do
    if ensure_ganache_ready; then
      break
    fi
    warn "Retrying Ganache startup in ${RESTART_DELAY}s..."
    sleep "$RESTART_DELAY"
  done

  $running || break

  info "Initializing Z3R0-N37-0M3GA... (attempt ${attempt})..."
  if launch_c2; then
    success "Z3R0-N37 exited cleanly; restarting in ${RESTART_DELAY}s."
  else
    exit_code=$?
    if ! $running; then
      break
    fi
    error "Z3R0-N37 exited with code ${exit_code}; restarting in ${RESTART_DELAY}s."
  fi

  ((attempt++))
  sleep "$RESTART_DELAY"
done

cleanup 0

