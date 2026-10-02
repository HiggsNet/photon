#!/usr/bin/env bash
# Explicit isolated IPv4 acceptance; no production identities or routing changes.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${PHOTON_WINDOWS_SSH:?Set SSH user@host}"
: "${PHOTON_LINUX_IP:?Set the Linux IP reachable from Windows}"
: "${PHOTON_WINDOWS_IP:?Set the Windows IP reachable from Linux}"
port=${PHOTON_CROSS_PORT:-43344}
[[ $port =~ ^[0-9]+$ && $PHOTON_LINUX_IP =~ ^[0-9.]+$ && $PHOTON_WINDOWS_IP =~ ^[0-9.]+$ ]] || exit 2
work=$(mktemp -d /tmp/photon-cross-host.XXXXXX)
name=$(basename "$work")
remote="C:/Windows/Temp/$name"
linux_pid= windows_pid=
ssh_args=(-o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR)
cleanup() {
    if [[ -n $windows_pid ]]; then
        ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoProfile -NonInteractive -Command \"New-Item -ItemType File -Force '$remote/stop' | Out-Null\"" >/dev/null 2>&1 || true
        wait "$windows_pid" || true
    fi
    if [[ -n $linux_pid ]]; then kill "$linux_pid" 2>/dev/null || true; wait "$linux_pid" 2>/dev/null || true; fi
    ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoProfile -NonInteractive -Command \"Remove-Item -Recurse -Force '$remote' -ErrorAction SilentlyContinue\"" || true
    # Test-only private identities are destroyed; retain only logs and source evidence.
    rm -rf "$work/state-tmp"
    rm -f "$work/right.db" "$work/manifest.json" "$work/cross.test.exe" "$work/cross.test"
    printf 'Cross-host logs: %s\n' "$work"
}
trap cleanup EXIT
export GOCACHE=${GOCACHE:-/tmp/photon-gocache}
CGO_ENABLED=0 go test -c -o "$work/cross.test" ./internal/photonwindows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go test -c -o "$work/cross.test.exe" ./internal/photonwindows
git rev-parse HEAD > "$work/source-commit.txt"
git status --short > "$work/source-status.txt"
mkdir "$work/state-tmp"
TMPDIR="$work/state-tmp" PHOTON_CROSS_ROLE=linux PHOTON_CROSS_DIR="$work" PHOTON_CROSS_LINUX="$PHOTON_LINUX_IP:$port" PHOTON_CROSS_WINDOWS="$PHOTON_WINDOWS_IP:$port" "$work/cross.test" -test.run='^TestCrossHostGossip$' -test.v -test.timeout=100s > "$work/linux.log" 2>&1 &
linux_pid=$!
for ((i=0;i<100;i++)); do [[ -f $work/ready ]] && break; kill -0 "$linux_pid" 2>/dev/null || { cat "$work/linux.log"; exit 1; }; sleep .1; done
[[ -f $work/ready ]]
ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoProfile -NonInteractive -Command \"New-Item -ItemType Directory '$remote' | Out-Null\""
scp -q -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR "$work/cross.test.exe" "$work/right.db" "$work/manifest.json" docs/scripts/windows-cross-host-smoke.ps1 "$PHOTON_WINDOWS_SSH:$remote/"
ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $remote/windows-cross-host-smoke.ps1 -LinuxAddress $PHOTON_LINUX_IP -Port $port" > "$work/windows.log" 2>&1 &
windows_pid=$!
for ((i=0;i<40;i++)); do
    if ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoProfile -NonInteractive -Command \"if (Test-Path '$remote/restarted') { exit 0 }; exit 1\""; then break; fi
    kill -0 "$windows_pid" 2>/dev/null || { cat "$work/windows.log"; exit 1; }
    sleep .5
done
touch "$work/verify"
wait "$linux_pid" || { cat "$work/linux.log"; exit 1; }; linux_pid=
ssh "${ssh_args[@]}" "$PHOTON_WINDOWS_SSH" "powershell.exe -NoProfile -NonInteractive -Command \"New-Item -ItemType File '$remote/stop' | Out-Null\""
wait "$windows_pid" || { cat "$work/windows.log"; exit 1; }; windows_pid=
cat "$work/linux.log" "$work/windows.log"
