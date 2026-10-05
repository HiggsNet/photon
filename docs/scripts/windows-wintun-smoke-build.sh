#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
output=$(mktemp -d "${TMPDIR:-/tmp}/photon-wintun-native.XXXXXX")
archive="$output/wintun-0.14.1.zip"
curl --fail --location --max-time 60 https://www.wintun.net/builds/wintun-0.14.1.zip -o "$archive"
printf '%s  %s\n' 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51 "$archive" | sha256sum --check --status
unzip -p "$archive" wintun/bin/amd64/wintun.dll > "$output/wintun.dll"
printf '%s  %s\n' e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce "$output/wintun.dll" | sha256sum --check --status
rm "$archive"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 GOCACHE="${GOCACHE:-/tmp/photon-gocache}" \
    go test -c -o "$output/wintun.test.exe" ./internal/photonwindows
cp docs/scripts/windows-wintun-smoke.ps1 "$output/run.ps1"
cp -R third_party "$output/"
git rev-parse HEAD > "$output/source-commit.txt"
git status --short > "$output/source-status.txt"
printf 'Wintun native smoke bundle: %s\n' "$output"
