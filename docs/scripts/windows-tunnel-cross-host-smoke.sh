#!/usr/bin/env bash
# A real Windows client against a disposable Linux kernel/StrongSwan responder.
# Only this container owns XFRM/routes. No host routes or production identities.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${PHOTON_WINDOWS_SSH:?Set SSH user@host for the Windows test VM}"
: "${PHOTON_LINUX_IP:?Set the Linux LAN IP reachable from Windows}"
ike_port=${PHOTON_WINDOWS_TUNNEL_IKE_PORT:-15000}
natt_port=${PHOTON_WINDOWS_TUNNEL_NATT_PORT:-14500}
[[ $PHOTON_LINUX_IP =~ ^[0-9.]+$ && $ike_port =~ ^[0-9]+$ && $natt_port =~ ^[0-9]+$ ]] || exit 2
[[ $ike_port -gt 1024 && $ike_port -lt 65536 && $natt_port -gt 1024 && $natt_port -lt 65536 && $ike_port != "$natt_port" ]] || exit 2
for port in "$ike_port" "$natt_port"; do
    if [[ -n $(ss -H -lun "sport = :$port") ]]; then
        printf 'UDP port %s is already occupied\n' "$port" >&2
        exit 1
    fi
done
work=$(mktemp -d /tmp/photon-windows-tunnel.XXXXXX)
name=$(basename "$work")
remote="$name"
smoke_image=${PHOTON_IKE_AUTH_IMAGE:-photon-ike-init-smoke:ubuntu24}
charon_binary=charon
docker_extra=()
if [[ -n ${PHOTON_IKE_AUTH_NIX_PACKAGE:-} ]]; then
    [[ $PHOTON_IKE_AUTH_NIX_PACKAGE == /nix/store/* && -x $PHOTON_IKE_AUTH_NIX_PACKAGE/libexec/ipsec/charon ]] || exit 2
    charon_binary="$PHOTON_IKE_AUTH_NIX_PACKAGE/libexec/ipsec/charon"
    docker_extra+=(--mount type=bind,src=/nix/store,dst=/nix/store,readonly)
fi
ssh_args=(-F /dev/null -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR)
container_started=0
remote_created=0
cleanup() {
    cleanup_status=$?
    if [[ $container_started == 1 ]]; then
        docker logs "$name" > "$work/fixture.log" 2>&1 || true
        docker exec "$name" cat /tmp/charon.log > "$work/charon.log" 2>&1 || true
        if ! docker rm -f "$name" >/dev/null 2>&1; then
            echo "Could not remove test container $name" >&2
            cleanup_status=1
        fi
    fi
    if [[ $remote_created == 1 ]]; then
        if ! ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"Remove-Item -LiteralPath '$remote' -Recurse -Force -ErrorAction Stop\""; then
            echo "Could not remove Windows test directory $remote" >&2
            cleanup_status=1
        fi
    fi
    rm -f "$work/windows.json" "$work/cross.test" "$work/cross.test.exe"
    printf 'Cross-host tunnel logs (no credentials): %s\n' "$work"
    exit "$cleanup_status"
}
trap cleanup EXIT
export GOCACHE=${GOCACHE:-/tmp/photon-gocache}
export GOMODCACHE=${GOMODCACHE:-/home/herbertqiao/go/pkg/mod}
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$work/cross.test" ./internal/photonwindows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go test -c -o "$work/cross.test.exe" ./internal/photonwindows
git rev-parse HEAD > "$work/source-commit.txt"
git status --short > "$work/source-status.txt"
if ! docker image inspect "$smoke_image" >/dev/null 2>&1; then
    docker build -t "$smoke_image" -f docs/scripts/ike-init-smoke.Dockerfile docs/scripts
fi
cat > "$work/strongswan.conf" <<'CONF'
charon {
    install_routes = no
    install_virtual_ip = no
    stderr { default = 1 }
    plugins {
        vici { socket = unix:///tmp/ike-auth.vici }
    }
}
CONF
if docker inspect "$name" >/dev/null 2>&1; then
    echo 'Unexpected existing test container name' >&2
    exit 1
fi
container_started=1
docker run -d --name "$name" --network bridge --cap-add NET_ADMIN \
    -p "$PHOTON_LINUX_IP:$ike_port:500/udp" -p "$PHOTON_LINUX_IP:$natt_port:4500/udp" \
    "${docker_extra[@]}" -v "$work:/smoke:ro" \
    -e "PHOTON_CHARON_BINARY=$charon_binary" \
    -e "PHOTON_WINDOWS_TUNNEL_GATEWAY=$PHOTON_LINUX_IP" \
    -e "PHOTON_WINDOWS_TUNNEL_IKE_PORT=$ike_port" \
    -e "PHOTON_WINDOWS_TUNNEL_NATT_PORT=$natt_port" \
    "$smoke_image" bash -euo pipefail -c '
        export STRONGSWAN_CONF=/smoke/strongswan.conf
        "$PHOTON_CHARON_BINARY" > /tmp/charon.log 2>&1 &
        charon_pid=$!
        trap '\''kill "$charon_pid" 2>/dev/null || true; wait "$charon_pid" || true'\'' EXIT
        for attempt in $(seq 1 50); do
            if [ -S /tmp/ike-auth.vici ]; then break; fi
            sleep 0.1
        done
        PHOTON_WINDOWS_TUNNEL_PREPARE=/tmp/windows.json /smoke/cross.test -test.run "^TestPrepareWindowsTunnelCrossHost$" -test.v -test.count=1
        touch /tmp/fixture-ready
        wait "$charon_pid"
    ' > "$work/container-id.txt"
ready=0
for ((attempt=0;attempt<100;attempt++)); do
    if docker exec "$name" test -f /tmp/fixture-ready 2>/dev/null; then ready=1; break; fi
    [[ $(docker inspect -f '{{.State.Running}}' "$name") == true ]] || { docker logs "$name"; exit 1; }
    sleep .1
done
[[ $ready == 1 ]] || { echo 'isolated responder startup timeout' >&2; exit 1; }
docker cp "$name:/tmp/windows.json" "$work/windows.json" >/dev/null
chmod 600 "$work/windows.json"
ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"New-Item -ItemType Directory '$remote' | Out-Null\""
remote_created=1
scp -q "${ssh_args[@]}" "$work/cross.test.exe" "$work/windows.json" docs/scripts/windows-tunnel-cross-host-smoke.ps1 "$PHOTON_WINDOWS_SSH:$remote/"
if ! ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $remote/windows-tunnel-cross-host-smoke.ps1" > "$work/windows.log" 2>&1; then
    cat "$work/windows.log"
    exit 1
fi
cat "$work/windows.log"
