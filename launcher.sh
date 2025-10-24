#!/usr/bin/env bash
# launch_ghost.sh
set -euo pipefail

PORT=7545
LOG=/tmp/ganache.log

# Kill any old Ganache
if lsof -i :$PORT >/dev/null 2>&1; then
  echo "[!] Port $PORT in use. Killing old process..."
  PID=$(lsof -ti :$PORT)
  sudo kill -9 $PID
  sleep 1
fi

# Start Ganache
echo "[+] Starting Ganache on port $PORT..."
nohup ganache --wallet.deterministic --port $PORT >$LOG 2>&1 &

# Wait until it responds
for i in {1..10}; do
  if curl -s http://127.0.0.1:$PORT > /dev/null; then
    echo "[+] Ganache is live."
    break
  fi
  sleep 1
done

# Launch blockchain utilities
echo "[+] Launching blockchain utils..."
python3 ~/projects/Z3R0-N37/blockchain_utils.py

# Launch Ghost_Comm
echo "[+] Starting Ghost_Comm..."
python3 ~/projects/Z3R0-N37/Ghost_Comm/main.py ghost_comm

