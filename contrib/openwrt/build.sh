#!/bin/sh
# Build portable Linux binaries; package architecture names come from the SDK.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_dir"
out_dir=${PHOTON_BUILD_DIR:-build/openwrt}
mkdir -p "$out_dir"
out_dir=$(CDPATH= cd -- "$out_dir" && pwd)
go_bin=${GO:-go}
commit=$(git rev-parse --short=12 HEAD)
describe=$(git describe --tags --always --dirty)
dirty=false
[ -z "$(git status --porcelain)" ] || dirty=true
build_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ldflags="-s -w -X main.buildCommit=$commit -X main.buildDescribe=$describe -X main.buildDirty=$dirty -X main.buildTime=$build_time"

if [ "$#" -eq 0 ]; then
	set -- amd64 386 armv5 armv6 armv7 arm64
fi
# Reject the whole request before starting a potentially long build.
for target do
	case "$target" in
		amd64|386|armv5|armv6|armv7|arm64|mips|mipsle) ;;
		*) printf 'Unsupported target: %s\n' "$target" >&2; exit 2 ;;
	esac
done

for target do
	arch=$target
	arm=5,softfloat
	case "$target" in
		armv5) arch=arm ;;
		armv6) arch=arm; arm=6,softfloat ;;
		armv7) arch=arm; arm=7,softfloat ;;
	esac
	printf 'Building %s\n' "$target"
	CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOAMD64=v1 GO386=softfloat \
		GOARM="$arm" GOARM64=v8.0 GOMIPS=softfloat GOENV=off GOTOOLCHAIN=local \
		"$go_bin" build -buildvcs=false -trimpath -ldflags "$ldflags" \
		-o "$out_dir/photon-linux-$target" ./app/photon
	(cd "$out_dir" && sha256sum "photon-linux-$target" > "photon-linux-$target.sha256")
done
# This manifest describes exactly this invocation's targets.
for target do
	cat "$out_dir/photon-linux-$target.sha256"
done > "$out_dir/SHA256SUMS"
