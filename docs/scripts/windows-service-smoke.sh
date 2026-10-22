#!/usr/bin/env bash
# Same disposable B4 gateway, production SCM executable and native IPC client.
set -euo pipefail
export PHOTON_WINDOWS_SMOKE_MODE=service
export PHOTON_WINDOWS_B6_GOSSIP=${PHOTON_WINDOWS_B6_GOSSIP:-1}
exec bash "$(dirname "$0")/windows-b4-cross-host-smoke.sh"
