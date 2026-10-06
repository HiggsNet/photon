#!/usr/bin/env bash
# Two disposable gateway namespaces, one signed Windows client, real A -> B switch.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${PHOTON_WINDOWS_SSH:?Set SSH user@Windows-VM}"
: "${PHOTON_LINUX_IP:?Set Linux LAN address reachable from Windows}"
: "${PHOTON_BIRD_NIX_PACKAGE:?Set local BIRD package under /nix/store}"
[[ $PHOTON_LINUX_IP =~ ^[0-9.]+$ && $PHOTON_BIRD_NIX_PACKAGE == /nix/store/* && -x $PHOTON_BIRD_NIX_PACKAGE/bin/bird ]] || exit 2
ports=("${PHOTON_B4_SWITCH_A_IKE:-15000}" "${PHOTON_B4_SWITCH_A_NATT:-14500}" "${PHOTON_B4_SWITCH_B_IKE:-15001}" "${PHOTON_B4_SWITCH_B_NATT:-14501}")
declare -A seen_ports=()
for port in "${ports[@]}"; do
    [[ $port =~ ^[0-9]+$ && $port -gt 1024 && $port -lt 65536 && -z ${seen_ports[$port]:-} ]] || exit 2
    seen_ports[$port]=1
    [[ -z $(ss -H -lun "sport = :$port") ]] || { echo "UDP port $port is occupied" >&2; exit 1; }
done
image=${PHOTON_IKE_AUTH_IMAGE:-photon-ike-init-smoke:ubuntu24}
charon=charon
if [[ -n ${PHOTON_IKE_AUTH_NIX_PACKAGE:-} ]]; then
    [[ $PHOTON_IKE_AUTH_NIX_PACKAGE == /nix/store/* && -x $PHOTON_IKE_AUTH_NIX_PACKAGE/libexec/ipsec/charon ]] || exit 2
    charon="$PHOTON_IKE_AUTH_NIX_PACKAGE/libexec/ipsec/charon"
fi
work=$(mktemp -d /tmp/photon-windows-switch.XXXXXX)
prefix=$(basename "$work")
remote=$prefix
ssh_args=(-F /dev/null -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR)
containers=()
remote_created=0
cleanup() {
    result=$?
    for container in "${containers[@]}"; do
        index=${container##*-}
        docker logs "$container" > "$work/$index-gateway.log" 2>&1 || true
        for item in bird.log traffic.json; do
            docker cp "$container:/tmp/b4/$item" "$work/$index-$item" >/dev/null 2>&1 || true
        done
        docker cp "$container:/tmp/charon.log" "$work/$index-charon.log" >/dev/null 2>&1 || true
        if ! docker rm -f "$container" >/dev/null; then result=1; fi
    done
    if [[ $remote_created == 1 ]]; then
        if ! ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"Remove-Item -LiteralPath '$remote' -Recurse -Force -ErrorAction Stop\""; then result=1; fi
    fi
    rm -f "$work/windows.db" "$work/config.json" "$work/config.json.tmp" "$work/b4.test" "$work/b4.test.exe" "$work/wintun.dll" "$work/wintun.zip" "$work/client-public.der" "$work/client-public.der.tmp"
    printf 'B4 gateway-switch logs (fixture secrets removed): %s\n' "$work"
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
for n in 0 1; do
    index=a
    if [[ $n == 1 ]]; then index=b; fi
    container="$prefix-$index"
    containers+=("$container")
    docker run -d --name "$container" --network bridge --cap-add NET_ADMIN \
        -p "$PHOTON_LINUX_IP:${ports[n*2]}:500/udp" -p "$PHOTON_LINUX_IP:${ports[n*2+1]}:4500/udp" \
        --mount type=bind,src=/nix/store,dst=/nix/store,readonly -v "$work:/smoke:ro" \
        -e "BIRD_BIN=$PHOTON_BIRD_NIX_PACKAGE/bin/bird" -e "BIRDC_BIN=$PHOTON_BIRD_NIX_PACKAGE/bin/birdc" \
        -e "PHOTON_CHARON_BINARY=$charon" -e "PHOTON_LINUX_IP=$PHOTON_LINUX_IP" \
        -e "PHOTON_BACKEND_IKE=${ports[n*2]}" -e "PHOTON_BACKEND_NATT=${ports[n*2+1]}" -e "PHOTON_B4_SWITCH_INDEX=$index" \
        "$image" bash -euo pipefail -c '
            export STRONGSWAN_CONF=/smoke/strongswan.conf
            mkdir -m 700 /tmp/b4
            "$PHOTON_CHARON_BINARY" > /tmp/charon.log 2>&1 &
            charon_pid=$!
            trap '\''kill "$charon_pid" 2>/dev/null || true; wait "$charon_pid" || true'\'' EXIT
            for attempt in $(seq 1 50); do
                if [ -S /tmp/ike-auth.vici ]; then break; fi
                sleep .1
            done
            PHOTON_B4_SWITCH_BACKEND=/tmp/b4 /smoke/b4.test -test.run "^TestServeWindowsB4SwitchBackend$" -test.v -test.count=1 -test.timeout=360s
        ' > "$work/$index-container-id.txt"
done
wait_file() {
    local container=$1 item=$2
    for ((attempt=0;attempt<200;attempt++)); do
        if docker exec "$container" test -f "/tmp/b4/$item" 2>/dev/null; then return; fi
        [[ $(docker inspect -f '{{.State.Running}}' "$container") == true ]] || { docker logs "$container"; return 1; }
        sleep .1
    done
    docker logs "$container"
    echo "Backend $container did not publish $item" >&2
    return 1
}
for index in a b; do
    wait_file "$prefix-$index" manifest.json
    docker cp "$prefix-$index:/tmp/b4/manifest.json" "$work/$index-manifest.json" >/dev/null
done
# Only public manifests enter preparation; backend private keys stay in containers.
PHOTON_B4_SWITCH_PREPARE="$work" "$work/b4.test" -test.run '^TestPrepareWindowsB4GatewaySwitch$' -test.v -test.count=1 -test.timeout=30s > "$work/prepare.log" 2>&1
for index in a b; do wait_file "$prefix-$index" ready; done
chmod 600 "$work/windows.db" "$work/config.json"
ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"New-Item -ItemType Directory '$remote' | Out-Null\""
remote_created=1
scp -q "${ssh_args[@]}" "$work/b4.test.exe" "$work/windows.db" "$work/config.json" "$work/wintun.dll" docs/scripts/windows-b4-gateway-switch-smoke.ps1 "$PHOTON_WINDOWS_SSH:$remote/"
if ! ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $remote/windows-b4-gateway-switch-smoke.ps1" > "$work/windows.log" 2>&1; then
    cat "$work/windows.log"
    exit 1
fi
cat "$work/windows.log"
for container in "${containers[@]}"; do
    [[ $(docker inspect -f '{{.State.Running}}' "$container") == true ]] || { docker logs "$container"; echo 'Backend stopped during signed gateway switch' >&2; exit 1; }
    index=${container##*-}
    docker cp "$container:/tmp/b4/traffic.json" "$work/$index-traffic.json" >/dev/null
done
PHOTON_B4_SWITCH_EVIDENCE="$work" "$work/b4.test" -test.run '^TestCheckWindowsB4GatewaySwitchEvidence$' -test.v -test.count=1 -test.timeout=10s > "$work/evidence.log" 2>&1
cat "$work/evidence.log"
