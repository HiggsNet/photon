#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
integration="$root/app/photon-flclash"
source "$integration/upstream.env"
target=${1:-"$root/build/photon-flclash/upstream"}
target=$(realpath -m -- "$target")
marker="$target/.photon-flclash"

if [[ -e "$target" ]]; then
  if [[ ! -f "$marker" ]] || [[ $(cat "$marker") != "$FLCLASH_COMMIT" ]]; then
    echo "Refusing to modify a checkout not prepared by Photon: $target" >&2
    exit 1
  fi
else
  mkdir -p -- "$(dirname -- "$target")"
  git clone --filter=blob:none --no-checkout -- "$FLCLASH_REPOSITORY" "$target"
  git -C "$target" fetch --depth 1 origin "$FLCLASH_COMMIT"
  git -C "$target" checkout --detach "$FLCLASH_COMMIT"
  printf '%s\n' "$FLCLASH_COMMIT" > "$marker"
fi

[[ $(git -C "$target" rev-parse HEAD) == "$FLCLASH_COMMIT" ]] || {
  echo 'FlClash checkout revision does not match upstream.env' >&2
  exit 1
}
git -C "$target" -c url.https://github.com/.insteadOf=git@github.com: \
  submodule update --init --recursive
[[ $(git -C "$target/core/Clash.Meta" rev-parse HEAD) == "$FLCLASH_MIHOMO_COMMIT" ]]
[[ $(git -C "$target/plugins/prism_ui" rev-parse HEAD) == "$FLCLASH_PRISM_COMMIT" ]]
if ! git -C "$target" apply --reverse --check "$integration/patches/photon.patch" 2>/dev/null; then
  git -C "$target" apply --check "$integration/patches/photon.patch"
  git -C "$target" apply "$integration/patches/photon.patch"
fi
cp -R -- "$integration/overlay/." "$target/"
printf 'Prepared FlClash %s + Photon at %s\n' "$FLCLASH_VERSION" "$target"
