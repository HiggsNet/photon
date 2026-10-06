#!/usr/bin/env bash
# A real Windows Daemon/Wintun client and disposable Linux StrongSwan/BIRD gateway.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${PHOTON_WINDOWS_SSH:?Set SSH user@Windows-VM}"
: "${PHOTON_LINUX_IP:?Set the Linux LAN address reachable from Windows}"
: "${PHOTON_BIRD_NIX_PACKAGE:?Set the local BIRD package under /nix/store}"
[[ $PHOTON_LINUX_IP =~ ^[0-9.]+$ && $PHOTON_BIRD_NIX_PACKAGE == /nix/store/* && -x $PHOTON_BIRD_NIX_PACKAGE/bin/bird ]] || exit 2
sadr_mode=${PHOTON_WINDOWS_B4_SADR:-0}
[[ $sadr_mode == 0 || $sadr_mode == 1 ]] || { echo "PHOTON_WINDOWS_B4_SADR must be 0 or 1" >&2; exit 2; }
ike_port=${PHOTON_WINDOWS_TUNNEL_IKE_PORT:-15000}
natt_port=${PHOTON_WINDOWS_TUNNEL_NATT_PORT:-14500}
[[ $ike_port =~ ^[0-9]+$ && $natt_port =~ ^[0-9]+$ && $ike_port -gt 1024 && $ike_port -lt 65536 && $natt_port -gt 1024 && $natt_port -lt 65536 && $ike_port != "$natt_port" ]] || exit 2
for port in "$ike_port" "$natt_port"; do
    [[ -z $(ss -H -lun "sport = :$port") ]] || { echo "UDP port $port is occupied" >&2; exit 1; }
done
work=$(mktemp -d /tmp/photon-windows-b4.XXXXXX)
name=$(basename "$work")
remote=$name
image=${PHOTON_IKE_AUTH_IMAGE:-photon-ike-init-smoke:ubuntu24}
charon=charon
if [[ -n ${PHOTON_IKE_AUTH_NIX_PACKAGE:-} ]]; then
    [[ $PHOTON_IKE_AUTH_NIX_PACKAGE == /nix/store/* && -x $PHOTON_IKE_AUTH_NIX_PACKAGE/libexec/ipsec/charon ]] || exit 2
    charon="$PHOTON_IKE_AUTH_NIX_PACKAGE/libexec/ipsec/charon"
fi
ssh_args=(-F /dev/null -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR)
container_started=0
remote_created=0
cleanup() {
    result=$?
    if [[ $container_started == 1 ]]; then
        docker logs "$name" > "$work/gateway.log" 2>&1 || true
        docker cp "$name:/tmp/b4/bird.log" "$work/bird.log" >/dev/null 2>&1 || true
        docker cp "$name:/tmp/charon.log" "$work/charon.log" >/dev/null 2>&1 || true
        if ! docker rm -f "$name" >/dev/null; then result=1; fi
    fi
    if [[ $remote_created == 1 ]]; then
        if ! ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"Remove-Item -LiteralPath '$remote' -Recurse -Force -ErrorAction Stop\""; then result=1; fi
    fi
    rm -f "$work/windows.db" "$work/config.json" "$work/b4.test" "$work/b4.test.exe" "$work/wintun.dll" "$work/wintun.zip"
    printf 'B4 cross-host logs (fixture secrets removed): %s\n' "$work"
    exit "$result"
}
trap cleanup EXIT
export GOCACHE=${GOCACHE:-/tmp/photon-gocache}
export GOMODCACHE=${GOMODCACHE:-/home/herbertqiao/go/pkg/mod}
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$work/b4.test" ./internal/photonwindows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go test -c -o "$work/b4.test.exe" ./internal/photonwindows
git rev-parse HEAD > "$work/source-commit.txt"
git status --short > "$work/source-status.txt"
curl --fail --location --max-time 60 https://www.wintun.net/builds/wintun-0.14.1.zip -o "$work/wintun.zip"
printf '%s  %s\n' 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51 "$work/wintun.zip" | sha256sum --check --status
unzip -p "$work/wintun.zip" wintun/bin/amd64/wintun.dll > "$work/wintun.dll"
printf '%s  %s\n' e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce "$work/wintun.dll" | sha256sum --check --status
cat > "$work/strongswan.conf" <<'CONF'
charon {
    install_routes = no
    install_virtual_ip = no
    stderr { default = 1 }
    plugins { vici { socket = unix:///tmp/ike-auth.vici } }
}
CONF
docker image inspect "$image" >/dev/null
container_started=1
docker run -d --name "$name" --network bridge --cap-add NET_ADMIN \
    -p "$PHOTON_LINUX_IP:$ike_port:500/udp" -p "$PHOTON_LINUX_IP:$natt_port:4500/udp" \
    --mount type=bind,src=/nix/store,dst=/nix/store,readonly -v "$work:/smoke:ro" \
    -e "PHOTON_WINDOWS_B4_SADR=$sadr_mode" \
    -e "BIRD_BIN=$PHOTON_BIRD_NIX_PACKAGE/bin/bird" -e "BIRDC_BIN=$PHOTON_BIRD_NIX_PACKAGE/bin/birdc" \
    -e "PHOTON_CHARON_BINARY=$charon" -e "PHOTON_WINDOWS_TUNNEL_GATEWAY=$PHOTON_LINUX_IP" \
    -e "PHOTON_WINDOWS_TUNNEL_IKE_PORT=$ike_port" -e "PHOTON_WINDOWS_TUNNEL_NATT_PORT=$natt_port" \
    "$image" bash -euo pipefail -c '
        export STRONGSWAN_CONF=/smoke/strongswan.conf
        mkdir -m 700 /tmp/b4
        "$PHOTON_CHARON_BINARY" > /tmp/charon.log 2>&1 &
        charon_pid=$!
        trap '\''kill "$charon_pid" 2>/dev/null || true; wait "$charon_pid" || true'\'' EXIT
        for attempt in $(seq 1 50); do
            if [ -S /tmp/ike-auth.vici ]; then break; fi
            sleep 0.1
        done
        PHOTON_WINDOWS_B4_FIXTURE=/tmp/b4 /smoke/b4.test -test.run "^TestServeWindowsB4Gateway$" -test.v -test.count=1 -test.timeout=420s
    ' > "$work/container-id.txt"
ready=0
for ((attempt=0;attempt<150;attempt++)); do
    if docker exec "$name" test -f /tmp/b4/ready 2>/dev/null; then ready=1; break; fi
    [[ $(docker inspect -f '{{.State.Running}}' "$name") == true ]] || { docker logs "$name"; exit 1; }
    sleep .1
done
[[ $ready == 1 ]] || { docker logs "$name"; echo 'B4 fixture startup timeout' >&2; exit 1; }
docker cp "$name:/tmp/b4/windows.db" "$work/windows.db" >/dev/null
docker cp "$name:/tmp/b4/config.json" "$work/config.json" >/dev/null
chmod 600 "$work/windows.db" "$work/config.json"
ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"New-Item -ItemType Directory '$remote' | Out-Null\""
remote_created=1
scp -q "${ssh_args[@]}" "$work/b4.test.exe" "$work/windows.db" "$work/config.json" "$work/wintun.dll" docs/scripts/windows-b4-cross-host-smoke.ps1 "$PHOTON_WINDOWS_SSH:$remote/"
if ! ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $remote/windows-b4-cross-host-smoke.ps1" > "$work/windows.log" 2>&1; then
    cat "$work/windows.log"
    exit 1
fi
cat "$work/windows.log"
