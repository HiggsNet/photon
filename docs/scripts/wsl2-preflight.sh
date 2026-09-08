#!/usr/bin/env bash
# Capability preflight for running Photon on standard WSL2.
#
# Unlike ipsec-xfrm-preflight.sh this script does NOT require XFRM
# interfaces (CONFIG_XFRM_INTERFACE), which stock WSL2 kernels lack.
# It instead verifies the policy-based XFRM surface used by the
# WSL2 backend. Run inside the WSL2 distribution, as root or with
# CAP_NET_ADMIN:
#
#   sudo docs/scripts/wsl2-preflight.sh
set -euo pipefail

vici_socket="${PHOTON_VICI_SOCKET:-/run/charon.vici}"
failures=0

check() {
  local name="$1"
  shift
  if "$@" >/tmp/photon-wsl2-preflight.out 2>&1; then
    printf '[ok]   %s\n' "$name"
  else
    printf '[fail] %s: ' "$name"
    tr '\n' ' ' </tmp/photon-wsl2-preflight.out
    printf '\n'
    failures=$((failures + 1))
  fi
}

note() {
  printf '[info] %s\n' "$1"
}

check "linux" test "$(uname -s)" = "Linux"
check "wsl kernel" sh -c 'uname -r | grep -qi microsoft'
check "root-or-cap-net-admin" bash -c '[ "$(id -u)" = 0 ] || { cap_eff="$(awk "/^CapEff:/ {print \$2}" /proc/self/status)"; cap=$((16#$cap_eff)); [ $((cap & (1 << 12))) -ne 0 ]; }'
check "ip command" command -v ip
check "kernel xfrm" sh -c 'test -e /proc/net/xfrm_stat || test -e /proc/net/xfrm_policy'
check "xfrm state/policy listing" sh -c 'ip xfrm state >/dev/null; ip xfrm policy >/dev/null'
check "tun device" sh -c 'test -c /dev/net/tun'
check "named netns create/delete" sh -c 'set -e; ns="photon-wsl2-preflight-$$"; trap "ip netns delete \"$ns\" >/dev/null 2>&1 || true" EXIT; ip netns add "$ns"; ip netns exec "$ns" true'

check "vici-socket" test -S "$vici_socket"
check "swanctl command" command -v swanctl
check "charon command" sh -c 'command -v charon || test -x /usr/lib/ipsec/charon'

if systemctl is-system-running >/dev/null 2>&1 || test -d /run/systemd/system; then
  note "systemd present: $(systemctl is-system-running 2>/dev/null || echo starting)"
else
  note "systemd not detected (enable [boot] systemd=true in /etc/wsl.conf for service-based deploys)"
fi

if ip link add phxxfrmprobe type xfrm if_id 1 >/dev/null 2>&1; then
  ip link delete phxxfrmprobe >/dev/null 2>&1 || true
  note "xfrm interfaces available on this kernel; the standard interface backend also works here"
else
  note "xfrm interfaces unavailable (expected on stock WSL2); use ipsec.xfrm_backend: policy"
fi

if ip link show eth0 >/dev/null 2>&1 && ip -4 addr show eth0 | grep -qE 'inet 172\.(1[6-9]|2[0-9]|3[01])\.'; then
  note "NAT networking detected (eth0 in 172.16.0.0/12): supported by this backend"
else
  note "networking mode not recognized as NAT; note that Mirrored mode is incompatible with the xfrm data plane (Hyper-V virtual switch), use NAT"
fi

rm -f /tmp/photon-wsl2-preflight.out

if [ "$failures" -ne 0 ]; then
  printf 'wsl2 preflight failed: %s check(s)\n' "$failures" >&2
  exit 1
fi

printf 'wsl2 preflight passed\n'
