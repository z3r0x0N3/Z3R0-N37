#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="/home/_0n3_/projects/Z3R0-N37"
cd "$REPO_ROOT"

LOG_DIR="${LOG_DIR:-/tmp}"
GANACHE_LOG="${GANACHE_LOG:-${LOG_DIR}/ganache.log}"

GANACHE_BIN="${GANACHE_BIN:-$(command -v ganache-cli || true)}"

if [[ -z "$GANACHE_BIN" ]]; then
    echo "start_ghost_comm_stack: ganache-cli not found in PATH; set GANACHE_BIN to override." >&2
    exit 1
fi

if ! pgrep -f "ganache-cli --deterministic" >/dev/null 2>&1; then
    nohup "$GANACHE_BIN" --deterministic >"$GANACHE_LOG" 2>&1 &
    sleep 5
fi

python3 blockchain_utils.py
exec python3 Ghost_Comm/main.py ghost_comm
