#!/usr/bin/env bash
# Windows SCM leaf against the complete Linux app/photon daemon in an isolated container.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${PHOTON_WINDOWS_SSH:?Set SSH user@Windows-VM}"
: "${PHOTON_LINUX_IP:?Set the Linux LAN address reachable from Windows}"
: "${PHOTON_BIRD_NIX_PACKAGE:?Set the local BIRD package under /nix/store}"
[[ $PHOTON_LINUX_IP =~ ^[0-9.]+$ && $PHOTON_BIRD_NIX_PACKAGE == /nix/store/* && -x $PHOTON_BIRD_NIX_PACKAGE/bin/bird ]] || exit 2
outage_mode=${PHOTON_WINDOWS_TRANSPORT_OUTAGE:-0}
rekey_mode=${PHOTON_WINDOWS_REKEY_TRAFFIC:-0}
impairment_mode=${PHOTON_WINDOWS_IMPAIRMENT:-0}
baseline_mode=${PHOTON_WINDOWS_BASELINE:-0}
throughput_mode=${PHOTON_WINDOWS_THROUGHPUT:-0}
throughput_seconds=${PHOTON_WINDOWS_THROUGHPUT_SECONDS:-15}
profile_mode=${PHOTON_WINDOWS_CPU_PROFILE:-0}
packet_drop_diagnostic=${PHOTON_WINDOWS_PACKET_DROP_DIAGNOSTIC:-0}
packet_timing_mode=${PHOTON_WINDOWS_PACKET_TIMING:-}
packet_timing_label=${PHOTON_WINDOWS_PACKET_TIMING_LABEL:-f1-w64-IPv4}
performance_bundle=${PHOTON_WINDOWS_PERFORMANCE_BUNDLE:-}
service_gomaxprocs=${PHOTON_WINDOWS_SERVICE_GOMAXPROCS:-}
service_affinity=${PHOTON_WINDOWS_SERVICE_AFFINITY:-}
thread_cpu=${PHOTON_WINDOWS_THREAD_CPU:-0}
performance_round=${PHOTON_WINDOWS_PERFORMANCE_ROUND:-1}
performance_sweep=${PHOTON_WINDOWS_PERFORMANCE_SWEEP:-}
[[ $thread_cpu == 0 || $thread_cpu == 1 ]] || exit 2
[[ $performance_round =~ ^[1-3]$ ]] || exit 2
[[ -z $service_gomaxprocs || $service_gomaxprocs =~ ^(1|2|4|8)$ ]] || exit 2
[[ -z $service_affinity || $service_affinity =~ ^(1|2|4|8)$ ]] || exit 2
if [[ $thread_cpu == 1 || -n $service_gomaxprocs || -n $service_affinity || -n $performance_sweep ]]; then
    [[ $throughput_mode == 1 && $profile_mode == 1 && $thread_cpu == 1 && $packet_drop_diagnostic == 0 ]] || { echo 'Runtime sweep requires throughput/profile/thread sampling without drop diagnostic' >&2; exit 2; }
    [[ $performance_sweep == gomaxprocs || $performance_sweep == affinity ]] || { echo 'Choose explicit gomaxprocs or affinity sweep' >&2; exit 2; }
    [[ -n $service_gomaxprocs && -n $service_affinity ]] || { echo 'Runtime sweep fixes both service Go P and logical CPU affinity' >&2; exit 2; }
    [[ $performance_sweep != gomaxprocs || $service_affinity == 8 ]] || exit 2
    [[ $performance_sweep != affinity || $service_gomaxprocs == 8 ]] || exit 2
fi
[[ $profile_mode == 0 || $profile_mode == 1 ]] || exit 2
[[ $packet_drop_diagnostic == 0 || $packet_drop_diagnostic == 1 ]] || exit 2
[[ $packet_drop_diagnostic == 0 || ( $throughput_mode == 1 && $profile_mode == 1 ) ]] || { echo 'Packet-drop diagnostic requires throughput and CPU profile modes' >&2; exit 2; }
if [[ -n $packet_timing_mode ]]; then
    [[ $packet_timing_mode == off || $packet_timing_mode == on ]] || { echo 'Packet timing mode must be off or on' >&2; exit 2; }
    [[ $packet_timing_label == f1-w64-IPv4 || $packet_timing_label == f4-w64-IPv4 ]] || { echo 'Packet timing requires a supported IPv4 small-window point' >&2; exit 2; }
    [[ $throughput_mode == 1 && $profile_mode == 1 && $packet_drop_diagnostic == 0 ]] || { echo 'Packet timing requires throughput and CPU profile without drop diagnostic' >&2; exit 2; }
elif [[ -n ${PHOTON_WINDOWS_PACKET_TIMING_LABEL:-} ]]; then
    echo 'Packet timing label requires an explicit off/on mode' >&2; exit 2
fi
[[ $profile_mode == 0 || $baseline_mode == 1 || $throughput_mode == 1 ]] || { echo 'CPU profile requires baseline or throughput mode' >&2; exit 2; }
[[ $rekey_mode == 0 || $rekey_mode == 1 ]] || exit 2
[[ $impairment_mode == 0 || $impairment_mode == 1 ]] || exit 2
[[ $baseline_mode == 0 || $baseline_mode == 1 ]] || exit 2
[[ $throughput_mode == 0 || $throughput_mode == 1 ]] || exit 2
[[ $throughput_seconds =~ ^[0-9]+$ && $throughput_seconds -ge 1 && $throughput_seconds -le 30 ]] || { echo 'Throughput seconds must be 1..30' >&2; exit 2; }
[[ $outage_mode == 0 || $outage_mode == 1 ]] || exit 2
if ((outage_mode + rekey_mode + impairment_mode + baseline_mode + throughput_mode > 1)); then
    echo 'Choose one independent B6 scenario: outage, rekey traffic, impairment, baseline, or throughput' >&2
    exit 2
fi
if [[ -n $performance_bundle ]]; then
    [[ $throughput_mode == 1 || $baseline_mode == 1 ]] || { echo 'Prebuilt performance bundle requires an explicit performance mode' >&2; exit 2; }
    for file in photon b4.test photon-windows.exe udp-perf udp-perf.exe performance-sources.json; do
        [[ -f $performance_bundle/$file && ! -L $performance_bundle/$file ]] || { echo "Missing regular bundle file: $file" >&2; exit 2; }
    done
fi
if [[ $outage_mode == 1 ]]; then
    : "${PHOTON_NFT_NIX_PACKAGE:?Set the local nftables package under /nix/store}"
    [[ $PHOTON_NFT_NIX_PACKAGE == /nix/store/* && -x $PHOTON_NFT_NIX_PACKAGE/bin/nft ]] || exit 2
    nft="$PHOTON_NFT_NIX_PACKAGE/bin/nft"
fi
if [[ $impairment_mode == 1 ]]; then
    : "${PHOTON_TC_NIX_PACKAGE:?Set the local iproute2 package under /nix/store}"
    : "${PHOTON_TCPDUMP_NIX_PACKAGE:?Set the local tcpdump package under /nix/store}"
    [[ $PHOTON_TC_NIX_PACKAGE == /nix/store/* && -x $PHOTON_TC_NIX_PACKAGE/bin/tc ]] || exit 2
    [[ $PHOTON_TCPDUMP_NIX_PACKAGE == /nix/store/* && -x $PHOTON_TCPDUMP_NIX_PACKAGE/bin/tcpdump ]] || exit 2
    command -v jq >/dev/null
    tc="$PHOTON_TC_NIX_PACKAGE/bin/tc"
    tcpdump="$PHOTON_TCPDUMP_NIX_PACKAGE/bin/tcpdump"
    source docs/scripts/windows-impairment-coordinator.sh
fi
gossip_port=${PHOTON_WINDOWS_GOSSIP_PORT:-15201}
ike_port=${PHOTON_WINDOWS_TUNNEL_IKE_PORT:-15000}
natt_port=${PHOTON_WINDOWS_TUNNEL_NATT_PORT:-14500}
[[ $ike_port =~ ^[0-9]+$ && $natt_port =~ ^[0-9]+$ && $ike_port -gt 1024 && $ike_port -lt 65536 && $natt_port -gt 1024 && $natt_port -lt 65536 && $ike_port != "$natt_port" ]] || exit 2
for port in "$ike_port" "$natt_port"; do
    [[ -z $(ss -H -lun "sport = :$port") ]] || { echo "UDP port $port is occupied" >&2; exit 1; }
done
[[ $gossip_port =~ ^[0-9]+$ && $gossip_port -gt 1024 && $gossip_port -lt 65536 && $gossip_port != "$ike_port" && $gossip_port != "$natt_port" ]] || exit 2
[[ -z $(ss -H -lun "sport = :$gossip_port") && -z $(ss -H -ltn "sport = :$gossip_port") ]] || { echo "Gossip fixture port is occupied" >&2; exit 1; }
gossip_args=(-p "$PHOTON_LINUX_IP:$gossip_port:5201/udp" -p "$PHOTON_LINUX_IP:$gossip_port:5201/tcp" -e "PHOTON_WINDOWS_GOSSIP_PORT=$gossip_port")
work=$(mktemp -d /tmp/photon-windows-full-daemon.XXXXXX)
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
outage_worker_pid=
rekey_worker_pid=
impairment_worker_pid=
outage_table="photon_outage_${name##*.}"
cleanup() {
    result=$?
    if [[ -n $impairment_worker_pid ]]; then
        kill "$impairment_worker_pid" 2>/dev/null || true
        wait "$impairment_worker_pid" 2>/dev/null || true
    fi
    if [[ $impairment_mode == 1 && $container_started == 1 ]]; then
        cleanup_impairment || result=1
        # Only public text summaries, never the fixture config or database.
        for phase in loss duplicate reorder; do
            for suffix in esp.txt capture.txt capture.done; do
                docker cp "$name:/tmp/b4/impairment-$phase-$suffix" "$work/impairment-$phase-$suffix" >/dev/null 2>&1 || true
            done
        done
    fi
    if [[ -n $rekey_worker_pid ]]; then
        kill "$rekey_worker_pid" 2>/dev/null || true
        wait "$rekey_worker_pid" 2>/dev/null || true
    fi
    if [[ -n $outage_worker_pid ]]; then
        kill "$outage_worker_pid" 2>/dev/null || true
        wait "$outage_worker_pid" 2>/dev/null || true
    fi
    if [[ $outage_mode == 1 && $container_started == 1 ]]; then
        if docker exec "$name" "$nft" list table inet "$outage_table" >/dev/null 2>&1; then
            docker exec "$name" "$nft" delete table inet "$outage_table" || result=1
        fi
    fi
    if [[ $container_started == 1 ]]; then
        # Stop the owned composition before charon; container removal is final fallback.
        docker exec "$name" bash -c '
            for file in /tmp/b4/throughput-echo4.pid /tmp/b4/throughput-echo6.pid /tmp/b4/daemon.pid /tmp/charon.pid; do
                if ! read -r pid < "$file"; then continue; fi
                [[ $pid =~ ^[0-9]+$ ]] || exit 1
                kill -TERM "$pid" 2>/dev/null || continue
                for ((i=0;i<50;i++)); do
                    kill -0 "$pid" 2>/dev/null || break
                    sleep .1
                done
            done
        ' >/dev/null 2>&1 || true
        docker logs "$name" > "$work/gateway.log" 2>&1 || true
        for file in bird.conf bird-parse.txt daemon.log linux-status.txt linux-identity.json linux-ports.json linux-routes.txt linux-xfrm.txt bird-routes.txt bird-entries.txt throughput-echo4.log throughput-echo6.log; do
            docker cp "$name:/tmp/b4/$file" "$work/$file" >/dev/null 2>&1 || true
        done
        docker cp "$name:/tmp/b4/bird.log" "$work/bird.log" >/dev/null 2>&1 || true
        docker cp "$name:/tmp/charon.log" "$work/charon.log" >/dev/null 2>&1 || true
        if ! docker rm -f "$name" >/dev/null; then result=1; fi
    fi
    if [[ $remote_created == 1 ]]; then
        # Only public runtime diagnostics; config.json contains fixture keys.
        for pattern in '*.log' '*-events.json' '*-diagnostics.json' '*-peers.json' '*-routes.json' '*-owned-network.json' 'crash-recovery.json' 'network-change.json' 'gossip-convergence.json' 'adapter-conflict.json' 'transport-outage.json' 'rekey-traffic*.json' 'impairment*.json' 'baseline*.json' 'throughput*.json' 'profile-*.pprof' 'profile-*.packet-drops.json' 'profile-*.packet-timing.json' 'profile-*.done' 'profile-*.error' 'runtime-*.json' 'runtime-*.error'; do
            scp -q "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH:$remote/$pattern" "$work/" 2>/dev/null || true
        done
        if ! ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"Remove-Item -LiteralPath '$remote' -Recurse -Force -ErrorAction Stop\""; then result=1; fi
    fi
    rm -f "$work/photon" "$work/windows.db" "$work/config.json" "$work/b4.test" "$work/b4.test.exe" "$work/photon-windows.exe" "$work/wintun.dll" "$work/wintun.zip" "$work/udp-perf" "$work/udp-perf.exe"
    printf 'Windows full-daemon cross-host logs (fixture secrets removed): %s\n' "$work"
    exit "$result"
}
trap cleanup EXIT
export GOCACHE=${GOCACHE:-/tmp/photon-gocache}
export GOMODCACHE=${GOMODCACHE:-/home/herbertqiao/go/pkg/mod}
profile_tags=()
if [[ $profile_mode == 1 ]]; then profile_tags=(-tags photon_profile); fi
if [[ -n $performance_bundle ]]; then
    for file in photon b4.test photon-windows.exe udp-perf udp-perf.exe performance-sources.json; do cp "$performance_bundle/$file" "$work/$file"; done
else
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$work/photon" ./app/photon
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$work/b4.test" ./internal/photonwindows
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build "${profile_tags[@]}" -o "$work/photon-windows.exe" ./app/photon-windows
    if [[ $throughput_mode == 1 ]]; then
        CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$work/udp-perf" ./docs/tools/udp-perf
        CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o "$work/udp-perf.exe" ./docs/tools/udp-perf
    fi
fi
if [[ $throughput_mode == 1 ]]; then
    sha256sum "$work/udp-perf" "$work/udp-perf.exe" > "$work/throughput-tools-sha256.txt"
fi
git rev-parse HEAD > "$work/source-commit.txt"
git status --short > "$work/source-status.txt"
sha256sum "$work/photon" "$work/b4.test" "$work/photon-windows.exe" > "$work/binaries-sha256.txt"
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
# Production XFRM setup writes only this container network namespace's sysctls.
docker run -d --name "$name" --network bridge --cap-add NET_ADMIN --security-opt systempaths=unconfined \
    -p "$PHOTON_LINUX_IP:$ike_port:500/udp" -p "$PHOTON_LINUX_IP:$natt_port:4500/udp" \
    "${gossip_args[@]}" \
    --mount type=bind,src=/nix/store,dst=/nix/store,readonly -v "$work:/smoke:ro" \
    -e "BIRD_BIN=$PHOTON_BIRD_NIX_PACKAGE/bin/bird" -e "BIRDC_BIN=$PHOTON_BIRD_NIX_PACKAGE/bin/birdc" \
    -e "PHOTON_CHARON_BINARY=$charon" -e "PHOTON_WINDOWS_TUNNEL_GATEWAY=$PHOTON_LINUX_IP" \
    -e "PHOTON_WINDOWS_TUNNEL_IKE_PORT=$ike_port" -e "PHOTON_WINDOWS_TUNNEL_NATT_PORT=$natt_port" \
    "$image" bash -euo pipefail -c '
        export STRONGSWAN_CONF=/smoke/strongswan.conf
        mkdir -m 700 /tmp/b4
        "$PHOTON_CHARON_BINARY" > /tmp/charon.log 2>&1 &
        charon_pid=$!
        echo "$charon_pid" > /tmp/charon.pid
        trap '\''kill "$charon_pid" 2>/dev/null || true; wait "$charon_pid" || true'\'' EXIT
        for attempt in $(seq 1 50); do
            if [ -S /tmp/ike-auth.vici ]; then break; fi
            sleep 0.1
        done
        export PHOTON_WINDOWS_FULL_DAEMON_FIXTURE=/tmp/b4
        export PHOTON_CONFIG=/tmp/b4/gateway.yaml
        export PHOTON_CONTROL_SOCKET=/tmp/b4/photon.sock
        export PATH="${BIRD_BIN%/*}:$PATH"
        /smoke/b4.test -test.run "^TestPrepareWindowsFullDaemonGateway$" -test.v -test.count=1
        ip addr add 198.18.253.1/32 dev lo
        ip -6 addr add fd00:7068:b4::1/128 dev lo nodad
        /smoke/photon daemon --interval 1 > /tmp/b4/daemon.log 2>&1 &
        daemon_pid=$!
        echo "$daemon_pid" > /tmp/b4/daemon.pid
        /smoke/b4.test -test.run "^TestServeFullDaemonEcho$" -test.v -test.count=1 -test.timeout=600s &
        echo_pid=$!
        trap '\''kill "$echo_pid" "$daemon_pid" "$charon_pid" 2>/dev/null || true; wait || true'\'' EXIT
        /smoke/b4.test -test.run "^TestObserveFullDaemonGateway$" -test.v -test.count=1 -test.timeout=300s &
        observer_pid=$!
        wait "$observer_pid"
        wait "$daemon_pid"

    ' > "$work/container-id.txt"
ready=0
for ((attempt=0;attempt<900;attempt++)); do
    if docker exec "$name" test -f /tmp/b4/control-ready 2>/dev/null; then ready=1; break; fi
    [[ $(docker inspect -f '{{.State.Running}}' "$name") == true ]] || { docker logs "$name"; exit 1; }
    sleep .1
done
[[ $ready == 1 ]] || { docker logs "$name"; echo 'Full daemon control and identity startup timeout' >&2; exit 1; }
docker cp "$name:/tmp/b4/windows.db" "$work/windows.db" >/dev/null
docker cp "$name:/tmp/b4/config.json" "$work/config.json" >/dev/null
docker cp "$name:/tmp/b4/gossip-evidence.json" "$work/gossip-evidence.json" >/dev/null
chmod 600 "$work/windows.db" "$work/config.json"
ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"New-Item -ItemType Directory '$remote' | Out-Null\""
remote_created=1
scp -q "${ssh_args[@]}" "$work/photon-windows.exe" "$work/windows.db" "$work/config.json" "$work/wintun.dll" "$work/gossip-evidence.json" docs/scripts/windows-service-smoke.ps1 "$PHOTON_WINDOWS_SSH:$remote/"
if [[ $baseline_mode == 1 ]]; then
    scp -q "${ssh_args[@]}" docs/scripts/windows-service-baseline.ps1 "$PHOTON_WINDOWS_SSH:$remote/"
fi
if [[ $throughput_mode == 1 ]]; then
    for family in 4 6; do
        if [[ $family == 4 ]]; then local_address=198.18.253.1; else local_address=fd00:7068:b4::1; fi
        docker exec -d "$name" bash -c 'echo $$ > "/tmp/b4/throughput-echo$2.pid"; exec /smoke/udp-perf -mode echo -local "$1" -port 19100 -flows 4 -seconds 900 -ready "/tmp/b4/throughput-echo$2.ready" > "/tmp/b4/throughput-echo$2.log" 2>&1' -- "$local_address" "$family"
        ready=0
        for ((attempt=0;attempt<50;attempt++)); do
            if docker exec "$name" test -f "/tmp/b4/throughput-echo$family.ready"; then ready=1;break;fi
            sleep .1
        done
        [[ $ready == 1 ]] || { echo "Throughput echo $family startup failed" >&2; exit 1; }
    done
    scp -q "${ssh_args[@]}" "$work/udp-perf.exe" docs/scripts/windows-service-throughput.ps1 "$PHOTON_WINDOWS_SSH:$remote/"
fi
if [[ $profile_mode == 1 ]]; then
    scp -q "${ssh_args[@]}" docs/scripts/windows-service-profile.ps1 "$PHOTON_WINDOWS_SSH:$remote/"
fi
if [[ $packet_drop_diagnostic == 1 ]]; then
    printf 'f4-w1024-IPv4\n' > "$work/fixture-packet-drop-profile"
    scp -q "${ssh_args[@]}" "$work/fixture-packet-drop-profile" "$PHOTON_WINDOWS_SSH:$remote/"
fi
if [[ -n $packet_timing_mode ]]; then
    printf '%s:%s\n' "$packet_timing_mode" "$packet_timing_label" > "$work/fixture-packet-timing-profile"
    scp -q "${ssh_args[@]}" "$work/fixture-packet-timing-profile" "$PHOTON_WINDOWS_SSH:$remote/"
fi
if [[ $thread_cpu == 1 ]]; then
    printf '%s\n' "$service_gomaxprocs" > "$work/fixture-gomaxprocs"
    printf '%s\n' "$service_affinity" > "$work/fixture-cpu-affinity"
    printf '250ms\n' > "$work/fixture-thread-cpu"
    printf '%s\n' "$performance_round" > "$work/fixture-performance-round"
    printf '%s\n' "$performance_sweep" > "$work/fixture-performance-sweep"
    scp -q "${ssh_args[@]}" "$work/fixture-gomaxprocs" "$work/fixture-cpu-affinity" "$work/fixture-thread-cpu" "$work/fixture-performance-round" "$work/fixture-performance-sweep" "$PHOTON_WINDOWS_SSH:$remote/"
fi
if [[ $rekey_mode == 1 ]]; then
    scp -q "${ssh_args[@]}" docs/scripts/windows-service-rekey-smoke.ps1 "$PHOTON_WINDOWS_SSH:$remote/"
    source docs/scripts/windows-rekey-coordinator.sh
    coordinate_rekey > "$work/rekey-coordinator.log" 2>&1 &
    rekey_worker_pid=$!
fi
if [[ $impairment_mode == 1 ]]; then
    scp -q "${ssh_args[@]}" docs/scripts/windows-service-impairment-smoke.ps1 "$PHOTON_WINDOWS_SSH:$remote/"
    coordinate_impairment > "$work/impairment-coordinator.log" 2>&1 &
    impairment_worker_pid=$!
fi
if [[ $outage_mode == 1 ]]; then
    scp -q "${ssh_args[@]}" docs/scripts/windows-service-outage-smoke.ps1 "$PHOTON_WINDOWS_SSH:$remote/"
    coordinate_outage() (
        trap - EXIT
        # The parent also deletes this exact table on every failure path.
        trap 'exit 1' TERM INT
        wait_phase() {
            local phase=$1 seconds=$2 value deadline=$((SECONDS + $2))
            while ((SECONDS < deadline)); do
                value=$(timeout 10 ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"if (Test-Path '$remote/outage-request.txt') { Get-Content '$remote/outage-request.txt' -Raw }\"") || return 1
                value=${value//$'\r'/}
                [[ $value == "$phase" ]] && return 0
                # The PS finally block may request restoration before block.
                [[ $phase == block && $value == restore ]] && return 1
                sleep 1
            done
            echo "Outage coordinator timed out waiting for $phase" >&2
            return 1
        }
        acknowledge() {
            timeout 10 ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"[IO.File]::WriteAllText((Join-Path (Get-Location) '$remote/outage-$1.ack'), '$1')\""
        }
        snapshot_sas() {
            local binary=swanctl
            if [[ -n ${PHOTON_IKE_AUTH_NIX_PACKAGE:-} ]]; then binary="$PHOTON_IKE_AUTH_NIX_PACKAGE/bin/swanctl"; fi
            # list-sas exposes public IDs/SPIs, never session keys.
            timeout 10 docker exec "$name" "$binary" --list-sas --uri unix:///tmp/ike-auth.vici > "$work/outage-$1-sas.txt"
            awk '/: #[0-9]+, ESTABLISHED, IKEv2/ {print $2}' "$work/outage-$1-sas.txt" | sort -u > "$work/outage-$1-ike-ids.txt"
            awk '/: #[0-9]+, reqid .* INSTALLED,/ {print $2}' "$work/outage-$1-sas.txt" | sort -u > "$work/outage-$1-child-ids.txt"
            [[ -s $work/outage-$1-ike-ids.txt && -s $work/outage-$1-child-ids.txt ]]
        }
        wait_phase block 90
        snapshot_sas before
        docker exec -i "$name" "$nft" -f - <<NFT
add table inet $outage_table
add chain inet $outage_table inbound { type filter hook input priority -10; policy accept; }
add chain inet $outage_table outbound { type filter hook output priority -10; policy accept; }
add rule inet $outage_table inbound iifname "eth0" udp dport 4500 udp length >= 12 @th,64,32 != 0 counter drop comment "natt-esp-in"
add rule inet $outage_table outbound oifname "eth0" udp sport 4500 udp length >= 12 @th,64,32 != 0 counter drop comment "natt-esp-out"
add rule inet $outage_table inbound iifname "eth0" udp dport { 500, 4500 } counter drop
add rule inet $outage_table inbound iifname "eth0" meta l4proto esp counter drop
add rule inet $outage_table outbound oifname "eth0" udp sport { 500, 4500 } counter drop
add rule inet $outage_table outbound oifname "eth0" meta l4proto esp counter drop
NFT
        acknowledge blocked
        wait_phase restore 120
        docker exec "$name" "$nft" list table inet "$outage_table" > "$work/outage-nft.txt"
        grep -Eq 'counter packets [1-9][0-9]*' "$work/outage-nft.txt"
        # A nonzero first payload word is an ESP SPI; IKE has a zero marker.
        # The length guard excludes NAT keepalive and truncated UDP payloads.
        for direction in in out; do
            grep -Eq "counter packets [1-9][0-9]*.*comment \"natt-esp-$direction\"" "$work/outage-nft.txt"
        done
        docker exec "$name" "$nft" delete table inet "$outage_table"
        if docker exec "$name" "$nft" list table inet "$outage_table" >/dev/null 2>&1; then exit 1; fi
        acknowledge restored
        wait_phase recovered 150
        snapshot_sas after
        for kind in ike child; do
            comm -13 "$work/outage-before-$kind-ids.txt" "$work/outage-after-$kind-ids.txt" > "$work/outage-new-$kind-ids.txt"
            [[ -s $work/outage-new-$kind-ids.txt ]]
        done
        acknowledge verified
    )
    coordinate_outage > "$work/outage-coordinator.log" 2>&1 &
    outage_worker_pid=$!
fi
remote_command="powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $remote/windows-service-smoke.ps1 -Executable $remote/photon-windows.exe -FixtureDirectory $remote"
if [[ $throughput_mode == 1 ]]; then remote_command+=" -ThroughputSeconds $throughput_seconds"; fi
if ! ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "$remote_command" > "$work/windows.log" 2>&1; then
    cat "$work/windows.log"
    exit 1
fi
cat "$work/windows.log"
if [[ -n $rekey_worker_pid ]]; then
    wait "$rekey_worker_pid"
    rekey_worker_pid=
fi
if [[ -n $impairment_worker_pid ]]; then
    wait "$impairment_worker_pid"
    impairment_worker_pid=
fi
if [[ -n $outage_worker_pid ]]; then
    wait "$outage_worker_pid"
    outage_worker_pid=
fi

# Captured during actual Windows service activity, before its final Stop.
docker exec "$name" test -f /tmp/b4/return-routes-ready
