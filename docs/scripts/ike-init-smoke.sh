#!/usr/bin/env bash
# Portable initiator against an isolated StrongSwan responder. No host networking.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo_root"
smoke_image="${PHOTON_IKE_INIT_IMAGE:-photon-ike-init-smoke:ubuntu24}"
smoke_dir="$(mktemp -d /tmp/photon-ike-init.XXXXXX)"
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
    default = 2
  }
  plugins {
    vici {
      socket = unix:///tmp/ike-init.vici
    }
  }
}
CONF
cat > "$smoke_dir/swanctl.conf" <<'CONF'
connections {
  photon-init {
    version = 2
    local_addrs = 127.0.0.1
    remote_addrs = 127.0.0.1
    # Deliberately omit proposals, matching the Linux connection generator.
    local {
      auth = pubkey
      id = photon-init-responder
    }
    remote {
      auth = pubkey
    }
  }
}
CONF
docker run --rm --network none --cap-add NET_ADMIN \
  -v "$smoke_dir:/smoke:ro" "$smoke_image" bash -euo pipefail -c '
    export STRONGSWAN_CONF=/smoke/strongswan.conf
    charon > /tmp/charon.log 2>&1 &
    charon_pid=$!
    trap '\''kill "$charon_pid" 2>/dev/null || true; wait "$charon_pid" || true; cat /tmp/charon.log'\'' EXIT
    for attempt in $(seq 1 50); do
      if [ -S /tmp/ike-init.vici ]; then break; fi
      sleep 0.1
    done
    swanctl --load-conns --file /smoke/swanctl.conf --uri unix:///tmp/ike-init.vici
    PHOTON_IKE_INIT_PEER=127.0.0.1:500 /smoke/ike.test -test.run "^TestStrongSwanSAInit$" -test.v -test.count=1
  '
