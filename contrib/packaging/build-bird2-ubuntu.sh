#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 ]]; then
  printf 'Usage: %s OUTPUT_DIRECTORY\n' "$0" >&2
  exit 2
fi

. /etc/os-release
case "$ID:$VERSION_CODENAME" in
  ubuntu:noble) upstream=2.14 ;;
  ubuntu:resolute) upstream=2.18 ;;
  *) printf 'Build on Ubuntu 24.04 (noble) or 26.04 (resolute).\n' >&2; exit 2 ;;
esac

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
photon_version=$(<"$repo/VERSION")
# Keep any release-candidate separator inside the Debian revision.
photon_version=${photon_version//-/\~}
mkdir -p "$1"
output=$(cd "$1" && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cd "$work"

# Use the signed Ubuntu source indexes for the current suite.
apt-get source --only-source --download-only bird2
sources=(bird2_"$upstream"-*.dsc)
if [[ ${#sources[@]} -ne 1 || ! -f ${sources[0]} ]]; then
  printf 'Expected Ubuntu %s to supply BIRD %s source.\n' "$VERSION_CODENAME" "$upstream" >&2
  exit 1
fi
source_dsc=${sources[0]}
source_version=${source_dsc#bird2_}
source_version=${source_version%.dsc}
package_version="$source_version+photon$photon_version"

dpkg-source -x "$source_dsc" bird2
cd bird2
patch_name=photon-babel-hysteresis.patch
install -D -m 0644 "$repo/patches/bird2-babel-hysteresis.patch" "debian/patches/$patch_name"
printf '\n%s\n' "$patch_name" >> debian/patches/series

{
  printf 'bird2 (%s) %s; urgency=medium\n\n' "$package_version" "$VERSION_CODENAME"
  printf '  * Add Babel route hysteresis and an independent ETX loss weight.\n\n'
  printf ' -- Photon Maintainers <photon@users.noreply.github.com>  %s\n\n' "$(date -R)"
  cat debian/changelog
} > debian/changelog.photon
mv debian/changelog.photon debian/changelog

# Build the binary package and record the corresponding source with the patch.
dpkg-buildpackage -G -us -uc
cd "$work"
architecture=$(dpkg --print-architecture)
asset_prefix="bird2-photon-ubuntu-$VERSION_ID"
deb="$asset_prefix-$architecture.deb"
source_bundle="$asset_prefix-source.tar.gz"
mv "bird2_${package_version}_${architecture}.deb" "$deb"
tar -czf "$source_bundle" "bird2_$package_version.dsc" \
  "bird2_$package_version.debian.tar.xz" bird2_"$upstream".orig.tar.*
sha256sum "$deb" > "${deb%.deb}.sha256"
sha256sum "$source_bundle" > "${source_bundle%.tar.gz}.sha256"
install -m 0644 "$deb" "${deb%.deb}.sha256" "$source_bundle" \
  "${source_bundle%.tar.gz}.sha256" "$output/"
