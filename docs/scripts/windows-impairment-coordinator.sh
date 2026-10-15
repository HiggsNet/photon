# Sourced by the isolated full-daemon rig; changes only its container eth0.
# Handles 71:/73: are owned by this fixture, never a host or VM interface.
cleanup_impairment() {
    [[ $container_started == 1 ]] || return 0
    docker exec "$name" bash -c '
        for file in /tmp/b4/impairment-*.pid; do
            [[ -f $file ]] || continue
            read -r pid < "$file"
            [[ $pid =~ ^[0-9]+$ ]] || exit 1
            [[ $(readlink "/proc/$pid/exe") == "$1" ]] || continue
            kill -INT "$pid" 2>/dev/null || true
            for ((i=0;i<50;i++)); do
                kill -0 "$pid" 2>/dev/null || break
                sleep .1
            done
        done
    ' -- "$tcpdump" >/dev/null 2>&1 || true
    if docker exec "$name" "$tc" -j qdisc show dev eth0 | jq -e 'any(.[]; .root == true and .handle == "71:" and .kind == "prio")' >/dev/null; then
        docker exec "$name" "$tc" qdisc del dev eth0 root handle 71:
    fi
}
coordinate_impairment() (
    trap - EXIT
    trap 'exit 1' TERM INT
    trap 'status=$?; printf "Impairment coordinator failed phase=%s line=%s status=%s\n" "${phase:-waiting}" "$LINENO" "$status" >&2; exit "$status"' ERR
    wait_impairment_phase() {
        local value deadline=$((SECONDS + 180))
        while ((SECONDS < deadline)); do
            value=$(timeout 10 ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"if (Test-Path '$remote/impairment-request.txt') { Get-Content '$remote/impairment-request.txt' -Raw }\"") || return 1
            value=${value//$'\r'/}
            [[ $value == "$1" ]] && return 0
            # A Windows finally restoration supersedes an unfinished apply.
            [[ $1 != restore-* && $value == "restore-$1" ]] && return 1
            sleep .2
        done
        echo "Impairment coordinator timed out waiting for $1" >&2
        return 1
    }
    acknowledge_impairment() {
        timeout 10 ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"[IO.File]::WriteAllText((Join-Path (Get-Location) '$remote/impairment-$1.ack'), '$1')\""
    }
    # Text-only packet summaries contain public outer addresses, SPI and sequence,
    # never packet payloads, pcap data or session keys. Observe post-qdisc eth0.
    for phase in loss duplicate reorder; do
        wait_impairment_phase "$phase"
        docker exec "$name" "$tc" -j qdisc show dev eth0 > "$work/impairment-$phase-before-qdisc.json"
        jq -e 'all(.[]; .root != true or .kind == "noqueue")' "$work/impairment-$phase-before-qdisc.json" >/dev/null
        docker exec "$name" "$tc" qdisc add dev eth0 root handle 71: prio bands 3 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
        # This fixture uses IPv4 outer IP headers without options. Bypass IKE's
        # zero non-ESP marker and UDP length 9 NAT keepalive before selecting ESP.
        docker exec "$name" "$tc" filter add dev eth0 parent 71: protocol ip prio 1 u32 match ip protocol 17 0xff match ip sport 4500 0xffff match u32 0 0xffffffff at 28 flowid 71:1
        docker exec "$name" "$tc" filter add dev eth0 parent 71: protocol ip prio 2 u32 match ip protocol 17 0xff match ip sport 4500 0xffff match u16 9 0xffff at 24 flowid 71:1
        docker exec "$name" "$tc" filter add dev eth0 parent 71: protocol ip prio 3 u32 match ip protocol 17 0xff match ip sport 4500 0xffff flowid 71:3
        case $phase in
            loss) netem_args=(loss 10%);;
            duplicate) netem_args=(duplicate 15%);;
            reorder) netem_args=(delay 40ms reorder 50% gap 5);;
        esac
        docker exec "$name" "$tc" qdisc add dev eth0 parent 71:3 handle 73: netem "${netem_args[@]}"
        docker exec "$name" "$tc" -j qdisc show dev eth0 > "$work/impairment-$phase-applied-qdisc.json"
        jq -e --arg phase "$phase" '
            [.[] | select(.kind == "netem" and .handle == "73:" and .parent == "71:3")] | length == 1' "$work/impairment-$phase-applied-qdisc.json" >/dev/null
        case $phase in
            loss) predicate='.options["loss-random"].loss == 0.1';;
            duplicate) predicate='.options.duplicate.duplicate == 0.15';;
            reorder) predicate='.options.delay.delay == 0.04 and .options.reorder.reorder == 0.5 and .options.gap == 5';;
        esac
        jq -e ".[] | select(.handle == \"73:\") | $predicate" "$work/impairment-$phase-applied-qdisc.json" >/dev/null
        docker exec "$name" "$tc" -s filter show dev eth0 parent 71: > "$work/impairment-$phase-filters.txt"
        docker exec -d "$name" bash -c '
            "$1" -nn -tt -l -s 96 -Q out -i eth0 "udp src port 4500" > "/tmp/b4/impairment-$2-esp.txt" 2> "/tmp/b4/impairment-$2-capture.txt" &
            pid=$!
            echo "$pid" > "/tmp/b4/impairment-$2.pid"
            wait "$pid"
            echo "$?" > "/tmp/b4/impairment-$2-capture.done"
        ' -- "$tcpdump" "$phase"
        ready=0
        for ((attempt=0;attempt<50;attempt++)); do
            if docker exec "$name" bash -c 'grep -q "listening on eth0" "/tmp/b4/impairment-$1-capture.txt"' -- "$phase"; then ready=1; break; fi
            sleep .1
        done
        [[ $ready == 1 ]] || { echo "Capture startup failed: $phase" >&2; exit 1; }
        acknowledge_impairment "$phase"
        wait_impairment_phase "restore-$phase"
        # Drain the bounded 40 ms delay before taking counters/removing qdisc.
        drained=0
        for ((attempt=0;attempt<30;attempt++)); do
            sleep .1
            docker exec "$name" "$tc" -s -j qdisc show dev eth0 > "$work/impairment-$phase-final-qdisc.json"
            if jq -e '.[] | select(.handle == "73:") | .qlen == 0' "$work/impairment-$phase-final-qdisc.json" >/dev/null; then drained=1; break; fi
        done
        [[ $drained == 1 ]]
        docker exec "$name" "$tc" -s qdisc show dev eth0 > "$work/impairment-$phase-final-qdisc.txt"
        jq -e '.[] | select(.handle == "73:") | .packets >= 1000 and .qlen == 0' "$work/impairment-$phase-final-qdisc.json" >/dev/null
        if [[ $phase == loss ]]; then
            jq -e '.[] | select(.handle == "73:") | .drops > 0' "$work/impairment-$phase-final-qdisc.json" >/dev/null
        else
            jq -e '.[] | select(.handle == "73:") | .drops == 0' "$work/impairment-$phase-final-qdisc.json" >/dev/null
        fi
        docker exec "$name" "$tc" qdisc del dev eth0 root handle 71:
        docker exec "$name" "$tc" -j qdisc show dev eth0 > "$work/impairment-$phase-restored-qdisc.json"
        jq -e 'all(.[]; .handle != "71:" and .handle != "73:")' "$work/impairment-$phase-restored-qdisc.json" >/dev/null
        docker exec "$name" bash -c 'read -r pid < "/tmp/b4/impairment-$1.pid"; [[ $pid =~ ^[0-9]+$ ]] && kill -INT "$pid"' -- "$phase"
        ready=0
        for ((attempt=0;attempt<50;attempt++)); do
            if docker exec "$name" test -f "/tmp/b4/impairment-$phase-capture.done"; then ready=1; break; fi
            sleep .1
        done
        [[ $ready == 1 ]]
        for suffix in esp.txt capture.txt capture.done; do
            docker cp "$name:/tmp/b4/impairment-$phase-$suffix" "$work/impairment-$phase-$suffix" >/dev/null
        done
        [[ $(cat "$work/impairment-$phase-capture.done") == 0 ]]
        docker exec "$name" rm -f "/tmp/b4/impairment-$phase.pid"
        grep -qx '0 packets dropped by kernel' "$work/impairment-$phase-capture.txt"
        awk '
            function hex(s, value,i,c) {
                sub(/^0x/, "", s); value=0
                for (i=1;i<=length(s);i++) { c=index("0123456789abcdef",tolower(substr(s,i,1)))-1; if(c<0) exit 1; value=value*16+c }
                return value
            }
            /UDP-encap: ESP\(spi=0x[0-9a-f]+,seq=0x[0-9a-f]+\)/ {
                line=$0; sub(/^.*ESP\(spi=/,"",line); split(line,fields,",")
                spi=fields[1]; seq=fields[2]; sub(/^seq=/,"",seq); sub(/\).*$/,"",seq)
                n=hex(seq); packets++; key=spi SUBSEP n
                if (seen[key]++) duplicates++
                if ((spi in maximum) && n<maximum[spi] && seen[key]==1) {
                    inversions++; lag=maximum[spi]-n; if(lag>maxlag) maxlag=lag
                }
                if (!(spi in maximum)) spis++
                if (!(spi in maximum) || n>maximum[spi]) maximum[spi]=n
            }
            END { printf "{\"esp_packets\":%d,\"spi_count\":%d,\"duplicate_spi_sequence\":%d,\"unique_sequence_inversions\":%d,\"max_unique_sequence_lag\":%d}\n",packets,spis,duplicates,inversions,maxlag }
        ' "$work/impairment-$phase-esp.txt" > "$work/impairment-$phase-wire.json"
        jq -e '.esp_packets >= 1000' "$work/impairment-$phase-wire.json" >/dev/null
        if [[ $phase == duplicate ]]; then jq -e '.duplicate_spi_sequence > 0' "$work/impairment-$phase-wire.json" >/dev/null; fi
        if [[ $phase == reorder ]]; then jq -e '.unique_sequence_inversions > 0 and .max_unique_sequence_lag < 64' "$work/impairment-$phase-wire.json" >/dev/null; fi
        acknowledge_impairment "restore-$phase"
    done
    wait_impairment_phase complete
    acknowledge_impairment complete
)
