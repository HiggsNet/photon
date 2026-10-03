#!/usr/bin/env bash
# Build a self-contained bundle to copy to Windows; no Go installation there is needed.
set -euo pipefail
cd "$(dirname "$0")/../.."
output=$(mktemp -d "${TMPDIR:-/tmp}/photon-windows-native.XXXXXX")
export GOOS=windows GOARCH=amd64 CGO_ENABLED=0
export GOCACHE="${GOCACHE:-/tmp/photon-gocache}"
for package in internal/photonwindows app/photon-windows internal/photonclient/ike internal/photonclient/esp; do
    mkdir -p "$output/$package"
    go test -c -o "$output/$package/native.test.exe" "./$package"
done
mkdir -p "$output/docs/photon-windows"
cp docs/photon-windows/config.example.yaml "$output/docs/photon-windows/"
cp docs/scripts/windows-native-smoke.ps1 "$output/run.ps1"
cp -R third_party "$output/"
git rev-parse HEAD > "$output/source-commit.txt"
git status --short > "$output/source-status.txt"
printf 'Windows native test bundle: %s\n' "$output"
