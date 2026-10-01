#!/usr/bin/env bash
set -euo pipefail

go_cmd="${GO:-go}"
go_cache="${GOCACHE:-/tmp/photon-gocache}"
go_mod_cache="${GOMODCACHE:-/tmp/photon-gomodcache}"

dump_diagnostics() {
  printf '\n[ipsec-xfrm-smoke] diagnostics\n' >&2
  ip netns list >&2 || true
  ip link show type xfrm >&2 || true
  ip xfrm state >&2 || true
  ip xfrm policy >&2 || true
  while read -r ns _; do
    [ -n "$ns" ] || continue
    printf '\n[ipsec-xfrm-smoke] namespace %s\n' "$ns" >&2
    ip netns exec "$ns" ip link >&2 || true
    ip netns exec "$ns" ip addr >&2 || true
    ip netns exec "$ns" ip route >&2 || true
  done < <(ip netns list 2>/dev/null || true)
  swanctl --list-sas >&2 || true
}

trap 'rc=$?; if [ "$rc" -ne 0 ]; then dump_diagnostics; fi; exit "$rc"' EXIT

docs/scripts/ipsec-xfrm-preflight.sh

PHOTON_IPSEC_XFRM_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./pkg/transport/ipsec -run '^TestSystemXFRMDriver(IntegrationSmoke|PeerTunnelPingSmoke)$' -count=1

PHOTON_IPSEC_XFRM_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./pkg/transport/ipsec -run '^TestStrongSwanDriverLoadsKeyAndConnection$' -count=1

PHOTON_IPSEC_XFRM_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./app/photon -run '^TestDaemonReconcileUsesSystemXFRMDriverSmoke$' -count=1

PHOTON_IPSEC_XFRM_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./pkg/transport/ipsec -run '^TestStrongSwan(DriverIKEBringup|AlgorithmInterop)Smoke$' -count=1 -v

PHOTON_IPSEC_XFRM_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./pkg/transport/ipsec -run '^TestStrongSwanBidirectionalTakeoverSmoke$' -count=1

PHOTON_IPSEC_XFRM_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./app/photon -run '^TestDaemonStrongSwanReconcileBringupSmoke$' -count=1

PHOTON_IPSEC_XFRM_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./app/photon -run '^TestDaemonStrongSwanPortRotationSmoke$' -count=1

PHOTON_IPSEC_XFRM_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./app/photon -run '^TestDaemonRunGossipStrongSwanBringupSmoke$' -count=1

PHOTON_IPSEC_XFRM_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./app/photon -run '^TestDaemonStrongSwanReconcileBringupDerivedPoolSmoke$' -count=1

if [ "${PHOTON_IPSEC_XFRM_SMOKE_CONTAINER:-0}" = "1" ]; then
  printf 'ipsec/xfrm smoke passed (preflight + SystemXFRMDriver lifecycle + peer tunnel ping SKIPPED in container + StrongSwan key/conn load + StrongSwan IKE bring-up + StrongSwan bidirectional takeover + daemon reconcile system apply + daemon StrongSwan/XFRM bring-up + daemon port rotation + daemon run gossip StrongSwan bring-up + derived-pool bring-up)\n'
else
  printf 'ipsec/xfrm smoke passed (preflight + SystemXFRMDriver lifecycle + peer tunnel ping + StrongSwan key/conn load + StrongSwan IKE bring-up + StrongSwan bidirectional takeover + daemon reconcile system apply + daemon StrongSwan/XFRM bring-up + daemon port rotation + daemon run gossip StrongSwan bring-up + derived-pool bring-up)\n'
fi
