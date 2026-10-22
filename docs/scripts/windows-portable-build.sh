#!/usr/bin/env bash
# Assemble a Windows amd64 bundle from explicit public inputs only.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"
build=${BUILD_DIR:-build}
mkdir -p -- "$build"
build=$(cd "$build" && pwd)
output="$build/windows-amd64"
archive="$build/photon-windows-amd64.zip"
archive_hash="$archive.sha256"
source_exe=${PHOTON_WINDOWS_EXE:-$output/photon-windows.exe}
version=0.14.1
zip_hash=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
dll_hash=e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce
stage=$(mktemp -d "$build/.windows-portable.XXXXXX")
publish_temp=
cleanup() {
    local status=$?
    trap - EXIT
    if [[ -n $publish_temp ]]; then rm -f -- "$publish_temp"; fi
    # This is exclusively the directory created by mktemp above, never output.
    rm -rf -- "$stage"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
fail() { printf '%s\n' "$*" >&2; exit 1; }
verify_hash() {
    local actual
    actual=$(sha256sum -- "$2")
    [[ ${actual%% *} == "$1" ]] || fail "SHA256 mismatch: $2"
}
ensure_directory() {
    [[ ! -L $1 ]] || fail "Refusing output directory symlink: $1"
    [[ ! -e $1 || -d $1 ]] || fail "Output directory is not a directory: $1"
    mkdir -p -- "$1"
}
publish_file() {
    local source=$1 target=$2 mode=${3:-0644}
    [[ ! -L $target && ( ! -e $target || -f $target ) ]] || fail "Refusing non-regular output: $target"
    publish_temp=$(mktemp "$(dirname "$target")/.photon-portable.XXXXXX")
    cat -- "$source" > "$publish_temp"
    chmod "$mode" "$publish_temp"
    # Replacing a read-only old package file needs directory permissions only.
    mv -f -- "$publish_temp" "$target"
    publish_temp=
}
command -v sha256sum >/dev/null
command -v zip >/dev/null
[[ -f $source_exe && ! -L $source_exe ]] || fail "Build the Windows executable first: $source_exe"
mkdir -p "$stage/package/third_party/wintun" "$stage/package/third_party/ranet-lite"
cp -- "$source_exe" "$stage/package/photon-windows.exe"
if [[ -n ${WINTUN_DLL:-} ]]; then
    [[ -f $WINTUN_DLL ]] || fail "WINTUN_DLL must name a local regular DLL: $WINTUN_DLL"
    cp -- "$WINTUN_DLL" "$stage/package/wintun.dll"
else
    command -v unzip >/dev/null
    cache="$build/downloads"
    ensure_directory "$cache"
    cached_zip="$cache/wintun-$version.zip"
    [[ ! -L $cached_zip && ( ! -e $cached_zip || -f $cached_zip ) ]] || fail "Refusing non-regular Wintun archive: $cached_zip"
    if [[ ! -f $cached_zip ]]; then
        command -v curl >/dev/null
        curl --fail --location --max-time 60 "https://www.wintun.net/builds/wintun-$version.zip" -o "$stage/wintun.zip"
        verify_hash "$zip_hash" "$stage/wintun.zip"
        publish_file "$stage/wintun.zip" "$cached_zip"
    fi
    verify_hash "$zip_hash" "$cached_zip"
    unzip -p "$cached_zip" wintun/bin/amd64/wintun.dll > "$stage/package/wintun.dll"
fi
verify_hash "$dll_hash" "$stage/package/wintun.dll"
cp -- docs/photon-windows/README.zh-CN.txt "$stage/package/README.zh-CN.txt"
cp -- docs/photon-windows/config.example.yaml "$stage/package/config.example.yaml"
files=(photon-windows.exe wintun.dll README.zh-CN.txt config.example.yaml)
for file in third_party/wintun/README.md third_party/wintun/LICENSE-go.txt third_party/wintun/LICENSE-binary.txt third_party/ranet-lite/README.md third_party/ranet-lite/LICENSE; do
    cp -- "$file" "$stage/package/$file"
    files+=("$file")
done
(
    cd "$stage/package"
    sha256sum -- "${files[@]}" > SHA256SUMS
    zip -q -X "$stage/photon-windows-amd64.zip" "${files[@]}" SHA256SUMS
)
(
    cd "$stage"
    sha256sum photon-windows-amd64.zip > photon-windows-amd64.zip.sha256
)
# Mirror only known package files. User config.yaml, state databases and other
# files in an existing output directory are neither traversed nor removed.
ensure_directory "$output"
ensure_directory "$output/third_party"
ensure_directory "$output/third_party/wintun"
ensure_directory "$output/third_party/ranet-lite"
for file in "${files[@]}" SHA256SUMS; do
    mode=0644
    [[ $file != photon-windows.exe ]] || mode=0755
    publish_file "$stage/package/$file" "$output/$file" "$mode"
done
publish_file "$stage/photon-windows-amd64.zip" "$archive"
publish_file "$stage/photon-windows-amd64.zip.sha256" "$archive_hash"
printf 'Portable directory: %s\nArchive: %s\nChecksum: %s\n' "$output" "$archive" "$archive_hash"
