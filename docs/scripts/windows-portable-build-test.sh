#!/usr/bin/env bash
# Local packaging regression; requires a freshly built exe and pinned DLL.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
source_exe=${PHOTON_WINDOWS_EXE:-$repo/build/windows-amd64/photon-windows.exe}
source_dll=${WINTUN_DLL:-$repo/build/windows-amd64/wintun.dll}
[[ $source_exe == /* ]] || source_exe="$repo/$source_exe"
[[ $source_dll == /* ]] || source_dll="$repo/$source_dll"
[[ -f $source_exe && -f $source_dll ]] || { echo 'First run make photon-windows-build, or provide PHOTON_WINDOWS_EXE and WINTUN_DLL.' >&2; exit 2; }
fixture=$(mktemp -d "${TMPDIR:-/tmp}/photon-portable-test.XXXXXX")
trap 'rm -rf -- "$fixture"' EXIT
build="$fixture/output with spaces"
output="$build/windows-amd64"
mkdir -p "$output/third_party/wintun"
cp -- "$source_exe" "$output/photon-windows.exe"
for file in config.yaml windows.db identity.key.json unrelated.txt third_party/wintun/private.key; do
    printf 'owned regression marker: %s\n' "$file" > "$output/$file"
done
BUILD_DIR="$build" WINTUN_DLL="$source_dll" bash "$repo/docs/scripts/windows-portable-build.sh" > "$fixture/first.log"
(
    cd "$build"
    sha256sum --check --status photon-windows-amd64.zip.sha256
)
unzip -tq "$build/photon-windows-amd64.zip" >/dev/null
unzip -q "$build/photon-windows-amd64.zip" -d "$fixture/unpacked"
(
    cd "$fixture/unpacked"
    sha256sum --check --status SHA256SUMS
)
expected=(photon-windows.exe wintun.dll README.zh-CN.txt config.example.yaml SHA256SUMS third_party/wintun/README.md third_party/wintun/LICENSE-go.txt third_party/wintun/LICENSE-binary.txt third_party/ranet-lite/README.md third_party/ranet-lite/LICENSE)
diff -u <(printf '%s\n' "${expected[@]}" | LC_ALL=C sort) <(unzip -Z1 "$build/photon-windows-amd64.zip" | LC_ALL=C sort)
cmp "$output/photon-windows.exe" "$fixture/unpacked/photon-windows.exe"
for file in config.yaml windows.db identity.key.json unrelated.txt third_party/wintun/private.key; do
    [[ $(cat "$output/$file") == "owned regression marker: $file" ]]
done
# Simulate a stale read-only license from an older unpacked package. Rebuild
# must replace only the package-owned file without chmodding arbitrary content.
printf 'old read-only notice\n' > "$output/third_party/wintun/LICENSE-go.txt"
chmod 0444 "$output/third_party/wintun/LICENSE-go.txt"
BUILD_DIR="$build" WINTUN_DLL="$source_dll" bash "$repo/docs/scripts/windows-portable-build.sh" > "$fixture/second.log"
cmp "$repo/third_party/wintun/LICENSE-go.txt" "$output/third_party/wintun/LICENSE-go.txt"
(
    cd "$output"
    sha256sum --check --status SHA256SUMS
)
zip_before=$(sha256sum "$build/photon-windows-amd64.zip")
checksum_before=$(cat "$build/photon-windows-amd64.zip.sha256")
printf 'incorrect DLL\n' > "$fixture/bad.dll"
if BUILD_DIR="$build" WINTUN_DLL="$fixture/bad.dll" bash "$repo/docs/scripts/windows-portable-build.sh" > "$fixture/bad-dll.log" 2>&1; then
    echo 'Incorrect offline DLL was accepted' >&2; exit 1
fi
grep -q 'SHA256 mismatch' "$fixture/bad-dll.log"
mkdir -p "$build/downloads"
printf 'incorrect cached archive\n' > "$build/downloads/wintun-0.14.1.zip"
if BUILD_DIR="$build" WINTUN_DLL= bash "$repo/docs/scripts/windows-portable-build.sh" > "$fixture/bad-archive.log" 2>&1; then
    echo 'Incorrect cached archive was accepted' >&2; exit 1
fi
grep -q 'SHA256 mismatch' "$fixture/bad-archive.log"
[[ $(sha256sum "$build/photon-windows-amd64.zip") == "$zip_before" ]]
[[ $(cat "$build/photon-windows-amd64.zip.sha256") == "$checksum_before" ]]
for file in config.yaml windows.db identity.key.json unrelated.txt third_party/wintun/private.key; do
    [[ $(cat "$output/$file") == "owned regression marker: $file" ]]
done
[[ -z $(find "$build" -maxdepth 1 -name '.windows-portable.*' -print -quit) ]]
echo WINDOWS_PORTABLE_BUILD_REGRESSION_PASS
