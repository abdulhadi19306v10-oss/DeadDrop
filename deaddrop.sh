#!/usr/bin/env bash
# DeadDrop CLI Launcher for Linux / Kali Linux
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$DIR/.venv/bin/python" ]; then
    exec "$DIR/.venv/bin/python" -m deaddrop.client.cli "$@"
elif command -v python3 &>/dev/null; then
    exec python3 -m deaddrop.client.cli "$@"
else
    echo "[!] Error: Python 3 not found. Please run ./install.sh first."
    exit 1
fi
