#!/usr/bin/env bash
# Stop Photon WSL2 client: daemon + charon.
set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "stopping photon daemon..."
pkill -f "photon daemon" 2>/dev/null || true

echo "stopping charon..."
pkill -x charon 2>/dev/null || true

sleep 1
echo "Photon WSL2 client stopped"
