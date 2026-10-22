#!/usr/bin/env bash
# Opt-in portable Windows leaf / real BIRD wire interoperability. No host routes.
set -euo pipefail
repo_root="$(git rev-parse --show-toplevel)"
work="$(mktemp -d "${TMPDIR:-/tmp}/photon-windows-babel.XXXXXX")"
container="photon-windows-babel-$$"
runtime="${PHOTON_CONTAINER_RUNTIME:-docker}"
image="${PHOTON_BIRD_IMAGE:-photon-interop:ubuntu24}"
cleanup() {
  local result=$? remaining
  if ! remaining="$("$runtime" ps -aq --filter "name=^${container}$")"; then
    printf '[windows-babel-interop] cannot verify container cleanup: %s\n' "$container" >&2
    result=1
  elif [ -n "$remaining" ] && ! "$runtime" rm -f "$container" >/dev/null; then
    printf '[windows-babel-interop] failed to remove container: %s\n' "$container" >&2
    result=1
  else
    printf '[windows-babel-interop] verified container absent: %s\n' "$container"
  fi
  rm -rf "$work"
  printf '[windows-babel-interop] removed temporary test binary\n'
  exit "$result"
}
trap cleanup EXIT
CGO_ENABLED=0 go test -c -o "$work/babel.test" "$repo_root/internal/photonclient/babel"
mounts=()
bird_bin=bird
birdc_bin=birdc
if [ -n "${PHOTON_BIRD_NIX_PACKAGE:-}" ]; then
  if [[ "$PHOTON_BIRD_NIX_PACKAGE" != /nix/store/* ]] || [ ! -x "$PHOTON_BIRD_NIX_PACKAGE/bin/bird" ] || [ ! -x "$PHOTON_BIRD_NIX_PACKAGE/bin/birdc" ]; then
    printf 'PHOTON_BIRD_NIX_PACKAGE must name a BIRD package in /nix/store\n' >&2
    exit 1
  fi
  mounts+=(-v /nix/store:/nix/store:ro)
  bird_bin="$PHOTON_BIRD_NIX_PACKAGE/bin/bird"
  birdc_bin="$PHOTON_BIRD_NIX_PACKAGE/bin/birdc"
fi
"$runtime" run --rm --name "$container" --privileged --userns=host --network none \
  "${mounts[@]}" -v "$work/babel.test:/babel.test:ro" \
  -e BIRD_BIN="$bird_bin" -e BIRDC_BIN="$birdc_bin" "$image" bash -ceu '
  "$BIRD_BIN" --version
  ip netns add bird
  ip link add leafph type veth peer name birdph
  ip link set birdph netns bird
  ip link set leafph up
  ip -6 addr flush dev leafph scope link
  ip -6 addr add fe80::1/64 dev leafph nodad
  ip netns exec bird ip link set lo up
  ip netns exec bird ip link set birdph up
  ip netns exec bird ip -6 addr flush dev birdph scope link
  ip netns exec bird ip -6 addr add fe80::2/64 dev birdph nodad
  cat >/tmp/bird.conf <<CONF
log stderr all;
router id 10.0.0.2;
protocol device { scan time 1; }
protocol static upstream4 { ipv4; route 198.51.100.0/24 blackhole; }
protocol static upstream6 { ipv6; route 2001:db8:beef::/64 blackhole; }
protocol babel leaf_interop {
 randomize router id yes;
 ipv4 { import all; export all; };
 ipv6 { import all; export all; };
 interface "birdph" { type wired; hello interval 1 s; update interval 4 s; rtt cost 0; };
}
CONF
  "$BIRD_BIN" -p -c /tmp/bird.conf
  ip netns exec bird "$BIRD_BIN" -f -c /tmp/bird.conf -s /tmp/bird.ctl &
  bird_pid=$!
  trap '\''kill "$bird_pid" 2>/dev/null || true; wait "$bird_pid" 2>/dev/null || true; ip netns del bird; ip link del leafph 2>/dev/null || true'\'' EXIT
  BIRD_PID="$bird_pid" PHOTON_BABEL_INTEROP=1 /babel.test -test.run "^TestBIRDLeafInterop$" -test.v -test.timeout 75s
  '
