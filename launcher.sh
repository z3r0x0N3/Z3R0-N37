#!/usr/bin/env bash
# launcher.sh — keep Ganache and Ghost_Comm running persistently until manually stopped.
set -Eeuo pipefail

PORT=${PORT:-7545}
LOG=/tmp/ganache.log
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BLOCKCHAIN_UTILS="${PROJECT_ROOT}/blockchain_utils.py"
GHOST_COMM_ENTRY="${PROJECT_ROOT}/Ghost_Comm/main.py"
RESTART_DELAY=${RESTART_DELAY:-5}

GANACHE_PID=""
GHOST_COMM_PID=""
running=true

log() {
  printf '[%s] %s\n' "$1" "$2"
}

kill_pid() {
  local pid="$1"
  if [[ -n "$pid" && "$(ps -p "$pid" -o comm= 2>/dev/null)" != "" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}

kill_port_processes() {
  if lsof -i :$PORT >/dev/null 2>&1; then
    log "!" "Port $PORT in use. Killing old process..."
    PID=$(lsof -ti :$PORT)
    sudo kill -9 $PID 2>/dev/null || true
    sleep 1
  fi
}

start_ganache() {
  kill_port_processes
  log "+" "Starting Ganache on port $PORT..."
  nohup ganache --wallet.deterministic --port $PORT >"$LOG" 2>&1 &
  GANACHE_PID=$!

  for i in {1..10}; do
    if curl -sf "http://127.0.0.1:$PORT" >/dev/null 2>&1; then
      log "+" "Ganache is live (PID $GANACHE_PID)."
      return 0
    fi
    sleep 1
  done

  log "!" "Ganache failed to start properly."
  return 1
}

run_blockchain_utils() {
  if [[ ! -f "$BLOCKCHAIN_UTILS" ]]; then
    log "!" "Missing blockchain utils at ${BLOCKCHAIN_UTILS}."
    return 1
  fi
  log "+" "Launching blockchain utils..."
  if ! python3 "$BLOCKCHAIN_UTILS"; then
    log "!" "blockchain_utils.py exited abnormally; continuing."
    return 1
  fi
  return 0
}

launch_ghost_comm() {
  if [[ ! -f "$GHOST_COMM_ENTRY" ]]; then
    log "!" "Ghost_Comm entrypoint missing at ${GHOST_COMM_ENTRY}."
    return 127
  fi

  # Launch Ghost_Comm persistently
  python3 "$GHOST_COMM_ENTRY" ghost_comm --persistent &
  GHOST_COMM_PID=$!

  # Wait for process to exit (only if it dies unexpectedly)
  wait "$GHOST_COMM_PID"
  local exit_code=$?
  GHOST_COMM_PID=""
  return "$exit_code"
}

cleanup() {
  log "+" "Shutting down launcher..."
  kill_pid "$GHOST_COMM_PID"
  kill_pid "$GANACHE_PID"
  running=false
  exit "${1:-0}"
}

trap 'cleanup 0' INT TERM
trap 'cleanup 0' TSTP

log "+" "Launcher online (persistent mode). Press Ctrl+C to stop."

# --- Persistent Mode Logic ---
if ! start_ganache; then
  log "!" "Ganache startup failed; exiting."
  exit 1
fi
run_blockchain_utils

log "+" "Starting Ghost_Comm persistently..."
launch_ghost_comm &
GHOST_COMM_PID=$!

# Monitor for crashes
while $running; do
  if ! ps -p "$GANACHE_PID" >/dev/null 2>&1; then
    log "!" "Ganache stopped unexpectedly; restarting in ${RESTART_DELAY}s..."
    sleep "$RESTART_DELAY"
    start_ganache
  fi

  if ! ps -p "$GHOST_COMM_PID" >/dev/null 2>&1; then
    log "!" "Ghost_Comm crashed; restarting in ${RESTART_DELAY}s..."
    sleep "$RESTART_DELAY"
    launch_ghost_comm &
    GHOST_COMM_PID=$!
  fi

  sleep 10
done

cleanup 0

