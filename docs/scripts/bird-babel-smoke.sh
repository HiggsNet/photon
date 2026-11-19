#!/usr/bin/env bash
# BIRD / Babel root smoke: runs real managed-BIRD tests that require root or
# CAP_NET_ADMIN + netns + BIRD 2.x. This is an explicit privileged integration
# target, NOT part of `make smoke-all`.
set -euo pipefail

go_cmd="${GO:-go}"
go_cache="${GOCACHE:-/tmp/photon-gocache}"
go_mod_cache="${GOMODCACHE:-/tmp/photon-gomodcache}"

dump_diagnostics() {
  printf '\n[bird-babel-smoke] diagnostics\n' >&2
  ip netns list >&2 || true
  for ns in $(ip netns list 2>/dev/null | awk '{print $1}' | grep '^photon-bird-' || true); do
    printf '\n--- netns %s ---\n' "$ns" >&2
    ip netns exec "$ns" ip addr 2>&1 || true
    ip netns exec "$ns" ip route 2>&1 || true
    ip netns exec "$ns" birdc show protocols 2>&1 || true
    ip netns exec "$ns" birdc show route 2>&1 || true
  done
}

trap 'rc=$?; if [ "$rc" -ne 0 ]; then dump_diagnostics; fi; exit "$rc"' EXIT

docs/scripts/bird-babel-preflight.sh

# Test 1: Managed BIRD lifecycle in a named netns
PHOTON_BIRD_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./pkg/routing/bird -run '^TestExecProcessManager(RootSmoke|DaemonLifecycle)$' -count=1 -v

# Test 2: Two-node BIRD Babel neighbor + route exchange via veth
PHOTON_BIRD_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./pkg/routing/bird -run '^TestBabelTwoNodeRootSmoke$' -count=1 -v

# Test 2b: veth upstream BIRD Babel neighbor + bidirectional prefix exchange
PHOTON_BIRD_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./pkg/routing/bird -run '^TestBIRDUpstreamBabelRootSmoke$' -count=1 -v

# Test 2c: BIRD/Babel import filter rejects unauthorized prefixes
PHOTON_BIRD_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./pkg/routing/bird -run '^TestBabelImportFilterNegativeRootSmoke$' -count=1 -v

# Test 2d: Anycast prefix failover without asserting ECMP
PHOTON_BIRD_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./pkg/routing/bird -run '^TestBabelAnycastFailoverRootSmoke$' -count=1 -v

# Test 3: Daemon routing reconcile with real BIRD in a netns
PHOTON_BIRD_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./app/photon -run '^TestDaemonBIRDRoutingRootSmoke$' -count=1 -v

# Test 4: Veth upstream with real BIRD
PHOTON_BIRD_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./app/photon -run '^TestDaemonBIRDUpstreamRootSmoke$' -count=1 -v

# Test 5: Daemon restart adopts the persisted managed BIRD process
PHOTON_BIRD_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./app/photon -run '^TestDaemonBIRDAdoptRestartRootSmoke$' -count=1 -v

printf 'bird/babel smoke passed (preflight + managed BIRD lifecycle + two-node Babel exchange + upstream Babel bidirectional prefix exchange + negative import filter + anycast failover + daemon routing reconcile + veth upstream + daemon restart adopt)\n'
