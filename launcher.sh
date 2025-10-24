#!/usr/bin/env bash
# launcher.sh - keep Ganache and Ghost_Comm running until manually stopped.
set -uo pipefail

PORT=${PORT:-7545}
GANACHE_LOG=${GANACHE_LOG:-/tmp/ganache.log}
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BLOCKCHAIN_UTILS="${PROJECT_ROOT}/blockchain_utils.py"
GHOST_COMM_ENTRY="${PROJECT_ROOT}/Ghost_Comm/main.py"
RESTART_DELAY=${RESTART_DELAY:-5}

running=true
GANACHE_PID=""
GHOST_COMM_PID=""

log() {
  printf '[%s] %s\n' "$1" "$2"
}

kill_pid() {
  local pid="$1"
  if [[ -z "$pid" ]]; then
    return 0
  fi

  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}

kill_port_processes() {
  local port="$1"
  local pids

  pids=$(lsof -ti :"$port" 2>/dev/null | tr '\n' ' ')
  if [[ -z "$pids" ]]; then
    return 0
  fi

  log "!" "Port ${port} in use. Terminating processes: ${pids}"
  while read -r pid; do
    [[ -z "$pid" ]] && continue
    if ! kill "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || log "!" "Failed to kill PID ${pid}; requires manual intervention."
    fi
  done <<<"$(printf '%s' "$pids" | tr ' ' '\n')"
  sleep 1
}

start_ganache() {
  kill_port_processes "$PORT"
  log "+" "Starting Ganache on port ${PORT}..."
  ganache --wallet.deterministic --port "$PORT" >"$GANACHE_LOG" 2>&1 &
  GANACHE_PID=$!
  log "+" "Ganache PID ${GANACHE_PID} (logging to ${GANACHE_LOG})."
}

wait_for_ganache() {
  for _ in {1..10}; do
    if curl -sf "http://127.0.0.1:${PORT}" >/dev/null 2>&1; then
      log "+" "Ganache is live."
      return 0
    fi
    sleep 1
  done
  log "!" "Ganache is not responding on port ${PORT}."
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

ensure_ganache_ready() {
  if [[ -n "$GANACHE_PID" ]] && kill -0 "$GANACHE_PID" 2>/dev/null; then
    if curl -sf "http://127.0.0.1:${PORT}" >/dev/null 2>&1; then
      return 0
    fi
    log "!" "Ganache (PID ${GANACHE_PID}) unresponsive; restarting..."
    kill_pid "$GANACHE_PID"
    GANACHE_PID=""
  fi

  start_ganache
  if wait_for_ganache; then
    run_blockchain_utils
    return 0
  fi

  return 1
}

launch_ghost_comm() {
  if [[ ! -f "$GHOST_COMM_ENTRY" ]]; then
    log "!" "Ghost_Comm entrypoint missing at ${GHOST_COMM_ENTRY}."
    return 127
  fi

  python3 "$GHOST_COMM_ENTRY" ghost_comm &
  GHOST_COMM_PID=$!
  wait "$GHOST_COMM_PID"
  local exit_code=$?
  GHOST_COMM_PID=""
  return "$exit_code"
}

cleanup() {
  local exit_code=${1:-0}
  if ! $running; then
    exit "$exit_code"
  fi

  running=false
  echo
  log "+" "Shutting down launcher..."
  kill_pid "$GHOST_COMM_PID"
  kill_pid "$GANACHE_PID"
  exit "$exit_code"
}

trap 'cleanup 0' INT TERM
trap 'cleanup 0' TSTP

log "+" "Launcher online. Press Ctrl+C to stop."

attempt=1
while $running; do
  while $running; do
    if ensure_ganache_ready; then
      break
    fi
    log "!" "Retrying Ganache startup in ${RESTART_DELAY}s..."
    sleep "$RESTART_DELAY"
  done

  $running || break

  log "+" "Starting Ghost_Comm (attempt ${attempt})..."
  if launch_ghost_comm; then
    log "!" "Ghost_Comm exited cleanly; restarting in ${RESTART_DELAY}s."
  else
    exit_code=$?
    if ! $running; then
      break
    fi
    log "!" "Ghost_Comm exited with code ${exit_code}; restarting in ${RESTART_DELAY}s."
  fi

  ((attempt++))
  sleep "$RESTART_DELAY"
done

cleanup 0
