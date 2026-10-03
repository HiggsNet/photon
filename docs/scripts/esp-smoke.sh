#!/usr/bin/env bash
# Real IPv4/IPv6 ESP data plane against isolated StrongSwan. No host network.
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo_root"
smoke_image="${PHOTON_ESP_IMAGE:-photon-ike-init-smoke:ubuntu24}"
charon_binary=charon
docker_extra=()
# Optional exact Nix package for matching the deployed StrongSwan version.
# The package and its runtime closure stay read-only inside the container.
if [[ -n "${PHOTON_ESP_NIX_PACKAGE:-}" ]]; then
  case "$PHOTON_ESP_NIX_PACKAGE" in
    /nix/store/*) ;;
    *) echo 'PHOTON_ESP_NIX_PACKAGE must be an absolute /nix/store package path' >&2; exit 1 ;;
  esac
  charon_binary="$PHOTON_ESP_NIX_PACKAGE/libexec/ipsec/charon"
  if [[ ! -x "$charon_binary" ]]; then
    echo 'Selected Nix package has no executable libexec/ipsec/charon' >&2
    exit 1
  fi
  docker_extra+=(--mount type=bind,src=/nix/store,dst=/nix/store,readonly)
fi
smoke_dir="$(mktemp -d /tmp/photon-esp.XXXXXX)"
trap 'rm -rf "$smoke_dir"' EXIT
GOCACHE="${GOCACHE:-/tmp/photon-gocache}" \
  GOMODCACHE="${GOMODCACHE:-/tmp/photon-gomodcache}" \
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  "${GO:-go}" test -c -o "$smoke_dir/ike.test" ./internal/photonclient/ike
if ! docker image inspect "$smoke_image" >/dev/null 2>&1; then
  docker build -t "$smoke_image" -f docs/scripts/ike-init-smoke.Dockerfile docs/scripts
fi
cat > "$smoke_dir/strongswan.conf" <<'CONF'
charon {
  install_routes = no
  install_virtual_ip = no
  stderr {
    default = 1
  }
  plugins {
    vici {
      socket = unix:///tmp/ike-auth.vici
    }
  }
}
CONF
docker run --rm --network none --cap-add NET_ADMIN \
  "${docker_extra[@]}" -e "PHOTON_CHARON_BINARY=$charon_binary" \
  -v "$smoke_dir:/smoke:ro" "$smoke_image" bash -euo pipefail -c '
    export STRONGSWAN_CONF=/smoke/strongswan.conf
    "$PHOTON_CHARON_BINARY" > /tmp/charon.log 2>&1 &
    charon_pid=$!
    trap '\''kill "$charon_pid" 2>/dev/null || true; wait "$charon_pid" || true; cat /tmp/charon.log'\'' EXIT
    for attempt in $(seq 1 50); do
      if [ -S /tmp/ike-auth.vici ]; then break; fi
      sleep 0.1
    done
    PHOTON_ESP_SMOKE=1 /smoke/ike.test -test.run "^TestStrongSwanESP$" -test.v -test.count=1
  '
