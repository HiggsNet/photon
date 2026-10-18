#!/bin/sh
# Run explicitly on a dedicated OpenWrt test device with Photon installed.
# Exercises the installed procd daemon, not a mock VICI client.
set -eu

[ "${PHOTON_OPENWRT_ACCEPTANCE:-}" = 1 ] || {
	echo 'Set PHOTON_OPENWRT_ACCEPTANCE=1 on a dedicated test device.' >&2
	exit 1
}
[ "$(id -u)" = 0 ] || exit 1
for command in ip unshare bash ubus jsonfilter uci nft sha256sum; do
	command -v "$command" >/dev/null
done
test -x /usr/sbin/photon
test -x /usr/lib/ipsec/charon
test ! -e /etc/photon/config.yaml
test ! -L /etc/photon/config.yaml
[ "$(uci -q get photon.main.config_file)" = /etc/photon/config.yaml ]
[ "$(uci -q get photon.main.enabled)" = 0 ]
[ -z "$(uci changes photon)" ]
if /etc/init.d/photon enabled; then
	echo 'Photon must have boot startup disabled before this test.' >&2
	exit 1
fi
initial=$(ubus call luci.photon snapshot '{}')
[ "$(printf '%s' "$initial" | jsonfilter -e '@.service.running')" = false ]

umask 077
test_dir=$(mktemp -d /tmp/photon-recovery.XXXXXX)
namespace=photon-recovery-$$
overlay_namespace=$namespace-overlay
test -z "$(ip netns list | awk -v name="$namespace" '$1 == name')"
test -z "$(ip netns list | awk -v name="$overlay_namespace" '$1 == name')"
echo "Acceptance artifacts: $test_dir"
cp -p /etc/config/photon "$test_dir/photon.uci.before"
ip -j link show > "$test_dir/links.before.json"
ip -j route show table all > "$test_dir/routes.before.json"
nft -s list ruleset > "$test_dir/firewall.before.nft"
cat /proc/self/mountinfo > "$test_dir/mountinfo.before"
sha256sum /etc/config/network /etc/config/firewall /etc/config/rpcd \
	/etc/config/dropbear /etc/config/uhttpd > "$test_dir/system-config.before.sha256"
charon_pid=
cleanup() {
	result=$?
	trap - EXIT
	set +e
	/etc/init.d/photon stop
	if [ -n "$charon_pid" ]; then
		kill -TERM "$charon_pid" 2>/dev/null
		wait "$charon_pid"
	fi
	rm -f "$test_dir/charon.vici"
	for owned_namespace in "$namespace" "$overlay_namespace"; do
		if ip netns list | awk -v name="$owned_namespace" '$1 == name' | grep -q .; then
			ip netns delete "$owned_namespace" || result=1
		fi
	done
	if [ -f "$test_dir/uci.owned.sha256" ] && sha256sum -c "$test_dir/uci.owned.sha256" >/dev/null 2>&1; then
		cp -p "$test_dir/photon.uci.before" /etc/config/photon || result=1
	else
		echo 'UCI changed unexpectedly; original saved for review.' >&2
		result=1
	fi
	/etc/init.d/photon disable
	if [ -f "$test_dir/config.owned.sha256" ] && sha256sum -c "$test_dir/config.owned.sha256" >/dev/null 2>&1; then
		rm /etc/photon/config.yaml "$test_dir/identity.key.json"
		if [ -e "$test_dir/state/photon.db" ]; then rm "$test_dir/state/photon.db"; fi
		if [ -d "$test_dir/state" ]; then rmdir "$test_dir/state" || result=1; fi
	else
		echo 'Test YAML changed unexpectedly; retained with its identity for review.' >&2
		result=1
	fi
	ip -j link show > "$test_dir/links.after.json"
	ip -j route show table all > "$test_dir/routes.after.json"
	nft -s list ruleset > "$test_dir/firewall.after.nft"
	cat /proc/self/mountinfo > "$test_dir/mountinfo.after"
	for item in links routes; do cmp "$test_dir/$item.before.json" "$test_dir/$item.after.json" || result=1; done
	cmp "$test_dir/firewall.before.nft" "$test_dir/firewall.after.nft" || result=1
	cmp "$test_dir/mountinfo.before" "$test_dir/mountinfo.after" || result=1
	cmp "$test_dir/photon.uci.before" /etc/config/photon || result=1
	sha256sum -c "$test_dir/system-config.before.sha256" || result=1
	ubus call luci.photon snapshot '{}' > "$test_dir/final-snapshot.json"
	if [ "$result" -eq 0 ]; then echo 'PASS recovery and exact device cleanup'; fi
	exit "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

photon gossip keygen "$test_dir/identity.key.json" > "$test_dir/keygen.log"
test_root_public_key=$(jsonfilter -i "$test_dir/identity.key.json" -e '@.public_key')
cat > /etc/photon/config.yaml <<EOF
data_dir: $test_dir/state
state_path: $test_dir/state/photon.db
trusted_root_public_key: $test_root_public_key
log:
  level: debug
  mode: stderr
gossip:
  peer_id: recovery.acceptance.invalid.
  listen_addr: "127.0.0.1:43436"
  init:
    managed_zone: recovery.acceptance.invalid.
    key_path: $test_dir/identity.key.json
  endpoint_discovery: loopback_only
  publish_endpoints: false
  reflectors: []
  bootstrap:
    - id: bootstrap.acceptance.invalid.
      addr: "127.0.0.1:43437"
netns:
  default:
    name: $overlay_namespace
    forwarding: {}
ipsec:
  driver: strongswan
  vici_socket: $test_dir/charon.vici
  port_mode: fixed
overlays:
  - id: recovery-acceptance
    reconcile:
      interval: 1s
    connect:
      - "strongswan://*.acceptance.invalid.?role=both&family=dual&mode=family-redundant"
EOF
sha256sum /etc/photon/config.yaml > "$test_dir/config.owned.sha256"
uci set photon.main.enabled=1
uci commit photon
sha256sum /etc/config/photon > "$test_dir/uci.owned.sha256"
ip netns add "$namespace"
ip netns exec "$namespace" ip link set lo up
mkdir "$test_dir/piddir"
cat > "$test_dir/strongswan.conf" <<EOF
charon {
  install_routes = no
  install_virtual_ip = no
  filelog {
    stderr {
      default = 1
      cfg = 2
      asn = -1
    }
  }
  plugins {
    vici {
      socket = unix://$test_dir/charon.vici
    }
  }
}
EOF
/etc/init.d/photon start
daemon_pid=
wait_state() {
	phase=$1
	expect_failure=$2
	for attempt in $(seq 1 30); do
		status=$(ubus call luci.photon snapshot '{}')
		online=$(printf '%s' "$status" | jsonfilter -e '@.daemon.daemon_online' || true)
		current_pid=$(printf '%s' "$status" | jsonfilter -e '@.service.pid')
		failure=$(printf '%s' "$status" | jsonfilter -e '@.daemon.last_link_failure.code' || true)
		if [ "$online" = true ] && { [ "$expect_failure" = "$failure" ]; }; then
			if [ -n "$daemon_pid" ]; then [ "$current_pid" = "$daemon_pid" ]; fi
			daemon_pid=$current_pid
			printf '%s\n' "$status" > "$test_dir/$phase.snapshot.json"
			echo "PASS $phase: same daemon PID=$daemon_pid, failure=${failure:-none}"
			return
		fi
		sleep 1
	done
	printf '%s\n' "$status" >&2
	echo "Timed out waiting for $phase" >&2
	exit 1
}
start_charon() {
	phase=$1
	unshare -m --propagation private ip netns exec "$namespace" bash -c \
		'mount --bind "$1" /run && STRONGSWAN_CONF="$2" exec /usr/lib/ipsec/charon' \
		bash "$test_dir/piddir" "$test_dir/strongswan.conf" > "$test_dir/$phase.charon.log" 2>&1 &
	charon_pid=$!
}
wait_subscription() {
	phase=$1
	for attempt in $(seq 1 30); do
		if grep -q ' registered for: child-updown' "$test_dir/$phase.charon.log" &&
		   grep -q ' registered for: ike-updown' "$test_dir/$phase.charon.log"; then
			sleep 2
			if grep -Eq ' unregistered for: (child|ike)-updown' "$test_dir/$phase.charon.log"; then
				echo 'Lifecycle subscription did not remain active.' >&2
				exit 1
			fi
			echo "PASS $phase: real charon confirms stable child-updown and ike-updown subscriptions"
			return
		fi
		sleep 1
	done
	echo "No real lifecycle subscriptions after $phase" >&2
	exit 1
}
wait_state before-charon ipsec_reconcile_failed
test ! -e "$test_dir/charon.vici"
start_charon delayed-start
wait_state delayed-start ''
wait_subscription delayed-start
kill -TERM "$charon_pid"
wait "$charon_pid"
charon_pid=
wait_state stopped-charon ipsec_reconcile_failed
start_charon restart
wait_state restart ''
wait_subscription restart
logread -e "photon\[$daemon_pid\]" > "$test_dir/photon.log"
grep -q 'vici_event_stream_closed' "$test_dir/photon.log"
echo 'PASS native procd Photon reconciles and resubscribes after delayed charon and restart, without restarting Photon'
