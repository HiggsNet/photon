#!/bin/sh
# Read-only inventory. Never creates interfaces, loads modules or edits rules.
set -u

failures=0
warnings=0
check() {
	check_name=$1
	shift
	if "$@" >/dev/null 2>&1; then
		printf '[ok] %s\n' "$check_name"
	else
		printf '[fail] %s\n' "$check_name"
		failures=$((failures + 1))
	fi
}
warn() {
	printf '[warn] %s\n' "$1"
	warnings=$((warnings + 1))
}

printf 'Photon OpenWrt / ImmortalWrt read-only inventory\n'
uname -srm
if [ -r /etc/openwrt_release ]; then
	# Print selected public fields without evaluating the release file as code.
	sed -n '/^DISTRIB_\(ID\|RELEASE\|TARGET\|ARCH\)=/p' /etc/openwrt_release
else
	warn '/etc/openwrt_release absent; this is not a target-firmware acceptance'
fi
awk '/^(MemTotal|MemAvailable):/ { print }' /proc/meminfo
df -Pk /etc /tmp 2>/dev/null || true
printf 'runtime path: '
readlink -f /run 2>/dev/null || true

check 'Linux' test "$(uname -s)" = Linux
check 'network namespace API present (creation not tested)' test -e /proc/self/ns/net
for tool in ip nft bird sysctl swanctl ping; do
	check "command: $tool" command -v "$tool"
done
check 'ip JSON link dump' ip -j link show
check 'ip JSON route dump' ip -j route show
check 'ip netns list' ip netns list
check 'XFRM kernel API (requires sufficient privilege)' ip xfrm policy list
check 'nft ruleset readable (contents suppressed)' nft list tables

if command -v bird >/dev/null 2>&1; then
	bird_version=$(bird --version 2>&1) || bird_version='unknown'
	printf 'BIRD: %s\n' "$bird_version"
	version=$(printf '%s\n' "$bird_version" | sed -n 's/.*BIRD version \([0-9][0-9.]*\).*/\1/p')
	major=${version%%.*}
	rest=${version#*.}
	minor=${rest%%.*}
	case "$major:$minor" in
		*[!0-9:]*|:*|*:) check 'BIRD version parseable' false ;;
		*) check 'BIRD >= 2.14' sh -c '[ "$1" -gt 2 ] || { [ "$1" -eq 2 ] && [ "$2" -ge 14 ]; }' sh "$major" "$minor" ;;
	esac
fi

vici_socket=${PHOTON_VICI_SOCKET:-/var/run/charon.vici}
check "VICI socket: $vici_socket" test -S "$vici_socket"
if command -v swanctl >/dev/null 2>&1 && [ -S "$vici_socket" ]; then
	check 'VICI statistics request' swanctl --stats --uri "unix://$vici_socket"
fi
for module in xfrm_interface veth; do
	if [ -d "/sys/module/$module" ]; then
		printf '[ok] kernel feature loaded/built-in: %s\n' "$module"
	else
		warn "$module not visible in /sys/module; availability is unproven (not loaded here)"
	fi
done
warn 'netns creation, XFRM if_id/move, crypto negotiation and firewall4 forwarding require isolated active tests'
warn 'persistent state capacity and flash write rate require device measurement'
printf 'Inventory complete: %s failure(s), %s warning(s). No network state changed.\n' "$failures" "$warnings"
[ "$failures" -eq 0 ]
