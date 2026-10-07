#!/usr/bin/env bash
# Same disposable B4 gateway, production SCM executable and native IPC client.
set -euo pipefail
export PHOTON_WINDOWS_SMOKE_MODE=service
exec bash "$(dirname "$0")/windows-b4-cross-host-smoke.sh"
