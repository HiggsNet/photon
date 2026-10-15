#!/usr/bin/env bash
# Test-only, deliberately restricted to the user's identified win11 VM.
set -euo pipefail
[[ $# == 2 && ( $1 == down || $1 == arm-only || $1 == restore ) ]] || exit 2
[[ ${PHOTON_PVE_SSH:-} == root@10.16.255.200 && ${PHOTON_PVE_VMID:-} == 101 ]] || exit 2
action=$1
work=$(realpath -e -- "$2")
[[ $work =~ ^/tmp/photon-windows-full-daemon\.[A-Za-z0-9]{6}$ && ! -L $2 ]] || exit 2
token=${work##*.}
[[ $token =~ ^[A-Za-z0-9]{6}$ ]] || exit 2
directory=/run/photon-win11-link-$token
marker=$work/pve-link-started
ssh_args=(-F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=7)
script=$(dirname "$(realpath "$0")")/windows-pve-link-guard.py
if [[ $action != restore ]]; then
    [[ ! -e $marker ]] || { echo 'Refusing a reused PVE fixture' >&2; exit 1; }
    ssh "${ssh_args[@]}" "$PHOTON_PVE_SSH" "umask 077; mkdir -- '$directory'"
    # A partial upload cannot have changed net0; mark only after a full upload.
    if ! scp -q "${ssh_args[@]}" "$script" "$PHOTON_PVE_SSH:$directory/guard.py"; then
        ssh "${ssh_args[@]}" "$PHOTON_PVE_SSH" "rm -f -- '$directory/guard.py'; rmdir -- '$directory'" || true
        exit 1
    fi
    : > "$marker"
    ssh "${ssh_args[@]}" "$PHOTON_PVE_SSH" "/usr/bin/python3 '$directory/guard.py' '$action' '$token'"
else
    [[ -e $marker ]] || exit 0
    ssh "${ssh_args[@]}" "$PHOTON_PVE_SSH" "/usr/bin/python3 '$directory/guard.py' restore '$token'"
    if ssh "${ssh_args[@]}" "$PHOTON_PVE_SSH" "test -f '$directory/state.json'"; then
        scp -q "${ssh_args[@]}" "$PHOTON_PVE_SSH:$directory/state.json" "$work/pve-link-state.json"
    fi
    scp -q "${ssh_args[@]}" "$PHOTON_PVE_SSH:$directory/events.jsonl" "$work/pve-link-events.jsonl"
    ssh "${ssh_args[@]}" "$PHOTON_PVE_SSH" "/usr/bin/python3 '$directory/guard.py' cleanup '$token'"
    rm -- "$marker"
fi
