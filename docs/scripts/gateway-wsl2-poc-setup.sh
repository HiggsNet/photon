#!/usr/bin/env bash
# Gateway side configuration for WSL2 Photon client PoC.
#
# This script sets up the persistent routes and firewall rules needed for
# the WSL2 client (policy backend) to communicate through the gateway.
#
# Usage: sudo bash gateway-wsl2-poc-setup.sh <client-tunnel-prefix> [phx-device]
#
# Example:
#   sudo bash gateway-wsl2-poc-setup.sh 10.60.0.0/24
#
# For IPv6 client prefix:
#   sudo bash gateway-wsl2-poc-setup.sh 2a0d:2905:1:61::/64
#
# The phx-device is auto-detected from the wsl2-poc overlay's xfrm policies.
# If not found, specify it explicitly.
set -euo pipefail

PREFIX="${1:?usage: gateway-wsl2-poc-setup.sh <client-tunnel-prefix> [phx-device]}"
PHX_DEV="${2:-}"

if [ "$(id -u)" != "0" ]; then
  echo "must run as root" >&2
  exit 1
fi

# Determine phx device for the wsl2-poc overlay
if [ -z "$PHX_DEV" ]; then
  # Find the phx device that has the wsl2-poc tunnel address
  PHX_DEV=$(ip netns exec photon ip -br addr show to "$PREFIX" 2>/dev/null | awk -F: '{print $2}' | tr -d ' ' | head -1)
fi
if [ -z "$PHX_DEV" ]; then
  echo "ERROR: no phx device found with address in $PREFIX" >&2
  echo "available phx devices:" >&2
  ip netns exec photon ip -br addr show | grep phx | head -10 >&2
  exit 1
fi
echo "using device: $PHX_DEV"

# Derive network address from prefix for firewall rules
NETWORK="${PREFIX%/*}"

# --- Routes ---
# Install return routes for the client's tunnel addresses.
# These routes direct traffic destined to the client's tunnel addresses
# through the correct XFRM interface.
# NOTE: These routes are not persistent across photon daemon restarts.
#       For production, the daemon's route installer should handle this.

# Extract the prefix as an ip route command argument
if echo "$PREFIX" | grep -q ':'; then
  # IPv6
  ROUTE_CMD="ip -6 route replace $PREFIX dev $PHX_DEV"
else
  # IPv4
  ROUTE_CMD="ip -4 route replace $PREFIX dev $PHX_DEV"
fi
ip netns exec photon eval "$ROUTE_CMD"
echo "route installed: $PREFIX dev $PHX_DEV"

# --- Firewall ---
# Insert rules BEFORE Photon's default-drop rules.
# These rules allow ESP-decapsulated traffic from the client's tunnel
# addresses. The conntrack state may be "invalid" for xfrm-decapsulated
# packets because the gateway didn't see the outbound direction.

# Input chain: allow client tunnel traffic to gateway local addresses
ip netns exec photon nft insert rule inet photon_default photon_default_input \
  ip saddr "$NETWORK/24" accept 2>/dev/null || \
ip netns exec photon nft insert rule inet photon_default photon_default_input \
  ip6 saddr "$PREFIX" accept 2>/dev/null || true

# Forward chain: allow transit (if forwarding is enabled)
ip netns exec photon nft insert rule inet photon_default photon_default_forward \
  ip saddr "$NETWORK/24" accept 2>/dev/null || \
ip netns exec photon nft insert rule inet photon_default photon_default_forward \
  ip6 saddr "$PREFIX" accept 2>/dev/null || true

# Accept invalid conntrack state for xfrm-decapsulated packets
ip netns exec photon nft insert rule inet photon_default photon_default_input \
  ip saddr "$NETWORK/24" ct state invalid accept 2>/dev/null || \
ip netns exec photon nft insert rule inet photon_default photon_default_input \
  ip6 saddr "$PREFIX" ct state invalid accept 2>/dev/null || true

echo "firewall rules added"
echo ""
echo "=== summary ==="
echo "device:    $PHX_DEV"
echo "prefix:    $PREFIX"
echo "routes:    installed via $PHX_DEV"
echo "firewall:  input + forward rules for $PREFIX"
echo ""
echo "NOTE: routes and firewall rules are not persistent across"
echo "      photon daemon restarts. Re-run this script after restart."
echo "      For production, integrate with Photon's route installer"
echo "      and firewall planner (Phase 2b/3)."
