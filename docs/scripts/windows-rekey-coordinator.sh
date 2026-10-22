# Sourced by the isolated full-daemon rig; owns no host network configuration.
coordinate_rekey() (
    trap - EXIT
    trap 'exit 1' TERM INT
    local binary=swanctl
    if [[ -n ${PHOTON_IKE_AUTH_NIX_PACKAGE:-} ]]; then binary="$PHOTON_IKE_AUTH_NIX_PACKAGE/bin/swanctl"; fi
    wait_rekey_phase() {
        local value deadline=$((SECONDS + 180))
        while ((SECONDS < deadline)); do
            value=$(timeout 10 ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"if (Test-Path '$remote/rekey-request.txt') { Get-Content '$remote/rekey-request.txt' -Raw }\"") || return 1
            value=${value//$'\r'/}
            [[ $value == "$1" ]] && return 0
            sleep 1
        done
        echo "Rekey coordinator timed out waiting for $1" >&2
        return 1
    }
    rekey_snapshot() {
        timeout 10 docker exec "$name" "$binary" --list-sas --uri unix:///tmp/ike-auth.vici > "$work/rekey-$1-sas.txt"
        awk '/: #[0-9]+, ESTABLISHED, IKEv2/ {gsub(/[# ,]/,"",$2); print $2}' "$work/rekey-$1-sas.txt" | sort -u > "$work/rekey-$1-ike.txt"
        awk '/: #[0-9]+, reqid .* INSTALLED,/ {gsub(/[# ,]/,"",$2); print $2}' "$work/rekey-$1-sas.txt" | sort -u > "$work/rekey-$1-child.txt"
    }
    for kind in child ike; do
        wait_rekey_phase "$kind"
        rekey_snapshot "before-$kind"
        [[ $(wc -l < "$work/rekey-before-$kind-$kind.txt") == 1 ]]
        local id
        read -r id < "$work/rekey-before-$kind-$kind.txt"
        [[ $id =~ ^[0-9]+$ ]]
        timeout 10 docker exec "$name" "$binary" --rekey "--$kind-id" "$id" --uri unix:///tmp/ike-auth.vici > "$work/rekey-$kind-command.txt"
        local deadline=$((SECONDS + 45)) success=0
        while ((SECONDS < deadline)); do
            rekey_snapshot "after-$kind"
            comm -13 "$work/rekey-before-$kind-$kind.txt" "$work/rekey-after-$kind-$kind.txt" > "$work/rekey-new-$kind.txt"
            # Require one established survivor and retirement of the old ID.
            if [[ $(wc -l < "$work/rekey-after-$kind-$kind.txt") == 1 && -s $work/rekey-new-$kind.txt ]]; then success=1; break; fi
            sleep .2
        done
        [[ $success == 1 ]]
        # CHILD rekey retains IKE; IKE rekey inherits the selected CHILD.
        local retained=ike
        [[ $kind == ike ]] && retained=child
        cmp "$work/rekey-before-$kind-$retained.txt" "$work/rekey-after-$kind-$retained.txt"
        timeout 10 ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"[IO.File]::WriteAllText((Join-Path (Get-Location) '$remote/rekey-$kind.ack'), '$kind')\""
    done
    wait_rekey_phase complete
)
