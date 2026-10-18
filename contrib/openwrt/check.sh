#!/bin/sh
# Development-host checks. procd is stubbed; this is not device acceptance.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
sh -n "$script_dir/build.sh" "$script_dir/preflight.sh" "$script_dir/files/photon.init" "$script_dir/files/photon.hotplug" "$script_dir/files/luci.photon"
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM

# Keep every fixture path and effect under the disposable directory.
sed -e "s|/usr/sbin/photon|$test_dir/photon|g" \
	-e "s|/run/photon|$test_dir/run|g" \
	"$script_dir/files/photon.init" > "$test_dir/photon.init"
printf '#!/bin/sh\nexit 0\n' > "$test_dir/photon"
chmod +x "$test_dir/photon"
touch "$test_dir/config with spaces.yaml"

TEST_CONFIG="$test_dir/config with spaces.yaml"
TEST_ENABLED=0
call_log="$test_dir/procd.log"
config_load() { [ "$1" = photon ]; }
config_get_bool() { enabled=$TEST_ENABLED; }
config_get() { config_file=$TEST_CONFIG; }
procd_open_instance() { printf 'instance <%s>\n' "$1" >> "$call_log"; }
procd_set_param() {
	printf '<%s>' "$@" >> "$call_log"
	printf '\n' >> "$call_log"
}
procd_close_instance() { printf 'close\n' >> "$call_log"; }
procd_add_reload_trigger() { printf 'trigger <%s>\n' "$1" >> "$call_log"; }
. "$test_dir/photon.init"

start_service
[ ! -e "$call_log" ]
[ ! -d "$test_dir/run" ]

TEST_ENABLED=1
TEST_CONFIG="$test_dir/absent.yaml"
if start_service 2>/dev/null; then
	echo 'missing config was accepted' >&2
	exit 1
fi
[ ! -e "$call_log" ]
TEST_CONFIG=relative.yaml
if start_service 2>/dev/null; then
	echo 'relative config was accepted' >&2
	exit 1
fi
[ ! -e "$call_log" ]

TEST_CONFIG="$test_dir/config with spaces.yaml"
start_service
grep -Fx "<command><$test_dir/photon><daemon>" "$call_log"
grep -Fx "<env><PHOTON_CONFIG=$TEST_CONFIG><PHOTON_CONTROL_SOCKET=$test_dir/run/photon.sock><PATH=/usr/sbin:/usr/bin:/sbin:/bin>" "$call_log"
grep -Fx "<file><$TEST_CONFIG></etc/config/photon><$test_dir/photon>" "$call_log"
grep -Fx '<respawn><3600><5><5>' "$call_log"
grep -Fx '<term_timeout><30>' "$call_log"
[ "$(grep -c '^instance ' "$call_log")" -eq 1 ]
[ -d "$test_dir/run/bird" ]
service_triggers
grep -Fx 'trigger <photon>' "$call_log"

# Cleanup failures must remain failed tasks instead of starting a replacement.
stop() { return 42; }
start() { touch "$test_dir/restarted"; }
if restart; then
	echo 'restart hid a failed stop/cleanup' >&2
	exit 1
fi
[ ! -e "$test_dir/restarted" ]
stop() { return 0; }
restart
[ -e "$test_dir/restarted" ]

# Invalid build targets are rejected without invoking a compiler.
if GO=/nonexistent PHOTON_BUILD_DIR="$test_dir/build" "$script_dir/build.sh" invalid-target > "$test_dir/build.log" 2>&1; then
	echo 'invalid target was accepted' >&2
	exit 1
fi
grep -q 'Unsupported target: invalid-target' "$test_dir/build.log"
printf 'OpenWrt host checks passed (procd calls stubbed).\n'
