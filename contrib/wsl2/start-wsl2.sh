#!/usr/bin/env bash
# Start Photon WSL2 client: charon + daemon.
# Requires: config.yaml and charon.conf already generated (see quickstart).
set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$INSTALL_DIR/env.sh"

CHARON_PID=""
PHOTON_PID=""

start_charon() {
	if pgrep -x charon > /dev/null; then
		echo "charon already running"
		return
	fi
	echo "starting charon..."
	# /run is volatile; recreate the socket parent on every boot.
	vici_socket="$(grep -oP 'socket = unix://\K.*' "$INSTALL_DIR/charon.conf" || true)"
	if [ -n "$vici_socket" ]; then
		mkdir -p "$(dirname "$vici_socket")"
	fi
	setsid nohup env \
		STRONGSWAN_CONF="$INSTALL_DIR/charon.conf" \
		/usr/lib/ipsec/charon \
		> "$INSTALL_DIR/charon.log" 2>&1 < /dev/null &
	sleep 2
	if [ ! -S "$(grep -oP 'socket = unix://\K.*' "$INSTALL_DIR/charon.conf")" ]; then
		echo "waiting for VICI socket..."
		sleep 3
	fi
	if ! pgrep -x charon > /dev/null; then
		echo "ERROR: charon failed to start" >&2
		exit 1
	fi
	echo "charon started"
}

start_photon() {
	if pgrep -f "photon daemon" > /dev/null; then
		echo "photon daemon already running"
		return
	fi
	echo "starting photon daemon..."
	setsid nohup env \
		PHOTON_CONFIG="$INSTALL_DIR/config.yaml" \
		PHOTON_CONTROL_SOCKET="$INSTALL_DIR/photon.sock" \
		"$PHOTON_BIN" daemon \
		> "$INSTALL_DIR/photon.log" 2>&1 < /dev/null &
	echo "photon daemon started"
}

mkdir -p "$INSTALL_DIR"
start_charon
sleep 1
start_photon

# Wait for initial sync
echo "waiting for mesh connectivity..."
sleep 15

if pgrep -f "photon daemon" > /dev/null && pgrep -x charon > /dev/null; then
	echo "Photon WSL2 client started successfully"
	echo "  config: $INSTALL_DIR/config.yaml"
	echo "  logs:   $INSTALL_DIR/{charon,photon}.log"
	echo "  status: $PHOTON_BIN links --verbose"
else
	echo "ERROR: startup failed, check logs" >&2
	exit 1
fi
