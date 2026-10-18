package photonlinux

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The outer test only starts a child with private mount/network namespaces.
// Every real address and route below belongs to that disposable child. In
// particular, an empty UpstreamRouteSpec.NetNS never means the device host.
func TestUpstreamOwnedReconcileRootSmoke(t *testing.T) {
	if os.Getenv("PHOTON_UPSTREAM_OWNERSHIP_SMOKE") != "1" {
		t.Skip("set PHOTON_UPSTREAM_OWNERSHIP_SMOKE=1 to run isolated kernel ownership acceptance")
	}
	if os.Getenv("PHOTON_UPSTREAM_OWNERSHIP_HELPER") != "1" {
		hostNS, err := os.Readlink("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "-m", "--propagation", "private", "-n", os.Args[0], "-test.run=^TestUpstreamOwnedReconcileRootSmoke$", "-test.v")
		cmd.Env = append(os.Environ(), "PHOTON_UPSTREAM_OWNERSHIP_HELPER=1", "PHOTON_UPSTREAM_OWNERSHIP_HOST_NETNS="+hostNS)
		out, err := cmd.CombinedOutput()
		t.Logf("isolated kernel acceptance:\n%s", out)
		if err != nil {
			t.Fatalf("isolated kernel acceptance: %v", err)
		}
		return
	}
	currentNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if hostNS := os.Getenv("PHOTON_UPSTREAM_OWNERSHIP_HOST_NETNS"); hostNS == "" || currentNS == hostNS {
		t.Fatal("ownership acceptance requires a distinct disposable network namespace")
	}
	t.Logf("disposable network namespace=%s", currentNS)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	smokeIP(t, ctx, "link", "set", "lo", "up")
	t.Run("shrink-clear-and-manager-rebuild", func(t *testing.T) {
		fixture := newUpstreamOwnedSmokeFixture(t, ctx, "ownlife")
		manager := newExecUpstreamRouteManager()
		full := fixture.desired()
		for range 2 {
			ensureUpstreamAfterDAD(t, ctx, manager, fixture, full)
			fixture.assertDesired(t, ctx, full)
		}
		shrunken := full
		shrunken.Prefixes = []netip.Prefix{full.Prefixes[1], full.Prefixes[3]}
		shrunken.SourcePrefixes = []netip.Prefix{full.SourcePrefixes[1], full.SourcePrefixes[3]}
		if err := manager.EnsureRoutes(ctx, shrunken); err != nil {
			t.Fatal(err)
		}
		fixture.assertDesired(t, ctx, shrunken)
		if err := manager.EnsureRoutes(ctx, fixture.empty()); err != nil {
			t.Fatal(err)
		}
		fixture.assertDesired(t, ctx, fixture.empty())
		ensureUpstreamAfterDAD(t, ctx, manager, fixture, full)
		// The new manager has no in-memory history of what installed these
		// objects. Ownership must be recovered from real kernel evidence.
		manager = newExecUpstreamRouteManager()
		if err := manager.EnsureRoutes(ctx, shrunken); err != nil {
			t.Fatal(err)
		}
		fixture.assertDesired(t, ctx, shrunken)
		manager = newExecUpstreamRouteManager()
		if err := manager.EnsureRoutes(ctx, fixture.empty()); err != nil {
			t.Fatal(err)
		}
		fixture.assertDesired(t, ctx, fixture.empty())
		t.Log("both families add/shrink/clear and fresh-manager cleanup passed; foreign static routes, addresses and link-local addresses retained")
	})
	t.Run("borrow-foreign-source-and-protect-route-conflict", func(t *testing.T) {
		fixture := newUpstreamOwnedSmokeFixture(t, ctx, "ownborrow")
		manager := newExecUpstreamRouteManager()
		desired := fixture.desired()
		desired.SourcePrefixes = append([]netip.Prefix(nil), fixture.foreignAddresses[:2]...)
		if err := manager.EnsureRoutes(ctx, desired); err != nil {
			t.Fatal(err)
		}
		fixture.assertForeign(t, ctx)
		if got := fixture.ownedAddresses(t, ctx); len(got) != 0 {
			t.Fatalf("borrowed foreign sources were retagged or duplicated: %+v", got)
		}
		if err := manager.EnsureRoutes(ctx, fixture.empty()); err != nil {
			t.Fatal(err)
		}
		fixture.assertDesired(t, ctx, fixture.empty())
		revoked := fixture.empty()
		revoked.Prefixes = []netip.Prefix{netip.MustParsePrefix("198.18.20.0/24"), netip.MustParsePrefix("fd42:242:20::/64")}
		if err := manager.EnsureRoutes(ctx, revoked); err != nil {
			t.Fatal(err)
		}
		fixture.assertDesired(t, ctx, revoked)
		conflict := fixture.empty()
		conflict.Prefixes = []netip.Prefix{fixture.foreignRoutes[0], fixture.foreignRoutes[1]}
		if err := manager.EnsureRoutes(ctx, conflict); err == nil {
			t.Fatal("same-prefix foreign static routes were silently adopted or replaced")
		}
		fixture.assertForeign(t, ctx)
		if got := fixture.ownedRoutes(t, ctx); len(got) != 0 {
			t.Fatalf("unrelated desired conflict prevented withdrawal of revoked owned routes: %+v", got)
		}
		if err := manager.EnsureRoutes(ctx, fixture.empty()); err != nil {
			t.Fatal(err)
		}
		fixture.assertDesired(t, ctx, fixture.empty())
		t.Log("pre-existing exact foreign sources borrowed without ownership; foreign route conflict reported and preserved while revoked owned routes were withdrawn")
	})
	t.Run("same-prefix-foreign-sibling-routes-survive-owned-delete", func(t *testing.T) {
		fixture := newUpstreamOwnedSmokeFixture(t, ctx, "ownsibling")
		manager := newExecUpstreamRouteManager()
		desired := fixture.desired()
		desired.SourcePrefixes = nil
		desired.Prefixes = []netip.Prefix{desired.Prefixes[0], desired.Prefixes[2]}
		if err := manager.EnsureRoutes(ctx, desired); err != nil {
			t.Fatal(err)
		}
		fixture.assertDesired(t, ctx, desired)
		foreign := make(map[string]string)
		for _, prefix := range desired.Prefixes {
			family := "-6"
			if prefix.Addr().Is4() {
				family = "-4"
			}
			smokeIP(t, ctx, family, "route", "add", prefix.String(), "dev", fixture.iface, "proto", "99", "metric", "4096")
			foreign[prefix.String()] = string(smokeIP(t, ctx, family, "-j", "route", "show", "exact", prefix.String(), "proto", "99"))
			if strings.TrimSpace(foreign[prefix.String()]) == "[]" {
				t.Fatalf("foreign same-prefix sibling %s was not installed", prefix)
			}
		}
		manager = newExecUpstreamRouteManager()
		if err := manager.EnsureRoutes(ctx, fixture.empty()); err != nil {
			t.Fatal(err)
		}
		fixture.assertDesired(t, ctx, fixture.empty())
		for _, prefix := range desired.Prefixes {
			family := "-6"
			if prefix.Addr().Is4() {
				family = "-4"
			}
			got := string(smokeIP(t, ctx, family, "-j", "route", "show", "exact", prefix.String(), "proto", "99"))
			if got != foreign[prefix.String()] {
				t.Fatalf("same-prefix foreign sibling %s changed: before=%s after=%s", prefix, foreign[prefix.String()], got)
			}
		}
		t.Log("both families deleted only owned proto242 routes; same-prefix proto99 siblings with distinct metrics remained byte-identical")
	})
	t.Run("ipv4-primary-must-not-delete-foreign-secondary", func(t *testing.T) {
		fixture := newUpstreamOwnedSmokeFixture(t, ctx, "ownprimary")
		manager := newExecUpstreamRouteManager()
		desired := fixture.empty()
		desired.SourcePrefixes = []netip.Prefix{netip.MustParsePrefix("10.242.30.1/24")}
		if err := manager.EnsureRoutes(ctx, desired); err != nil {
			t.Fatal(err)
		}
		secondary := netip.MustParsePrefix("10.242.30.99/24")
		smokeIP(t, ctx, "-4", "addr", "add", secondary.String(), "dev", fixture.iface, "proto", "99")
		// Verify the kernel condition is really present. Changing a sysctl to
		// bypass the condition would hide this safety requirement.
		before := smokeAddresses(t, ctx, fixture.iface)
		if !before[secondary.String()].Secondary {
			t.Fatal("foreign fixture is not an IPv4 secondary")
		}
		if err := manager.EnsureRoutes(ctx, fixture.empty()); err == nil {
			t.Fatal("owned primary cleanup did not reject a live foreign secondary")
		}
		after := smokeAddresses(t, ctx, fixture.iface)
		for _, prefix := range []netip.Prefix{desired.SourcePrefixes[0], secondary} {
			if !reflect.DeepEqual(before[prefix.String()], after[prefix.String()]) {
				t.Fatalf("unsafe primary cleanup changed address %s: before=%+v after=%+v", prefix, before, after)
			}
		}
		fixture.assertForeign(t, ctx)
		t.Log("clear returned an error and retained both owned IPv4 primary and foreign same-subnet secondary")
	})
	t.Run("foreign-route-prefsrc-protects-owned-address", func(t *testing.T) {
		for _, family := range []string{"-4", "-6"} {
			for _, table := range []string{"main", "123"} {
				t.Run(family+"/table="+table, func(t *testing.T) {
					fixture := newUpstreamOwnedSmokeFixture(t, ctx, "ownsrc"+family[1:]+table)
					manager := newExecUpstreamRouteManager()
					source := netip.MustParsePrefix("10.242.40.1/32")
					prefix := "198.19.40.0/24"
					if family == "-6" {
						source = netip.MustParsePrefix("fd42:242:40::1/128")
						prefix = "fd42:242:40:1::/64"
					}
					desired := fixture.empty()
					desired.SourcePrefixes = []netip.Prefix{source}
					if err := manager.EnsureRoutes(ctx, desired); err != nil {
						t.Fatal(err)
					}
					waitUpstreamDAD(t, ctx, fixture.iface, desired.SourcePrefixes)
					smokeIP(t, ctx, family, "route", "add", prefix, "table", table, "dev", fixture.iface, "proto", "static", "src", source.Addr().String())
					beforeRoute := string(smokeIP(t, ctx, family, "-j", "route", "show", "table", table, "exact", prefix))
					beforeAddress := smokeAddresses(t, ctx, fixture.iface)[source.String()]
					for range 2 {
						manager = newExecUpstreamRouteManager()
						if err := manager.EnsureRoutes(ctx, fixture.empty()); err == nil {
							t.Fatalf("clear removed source referenced by foreign %s route in table %s", family, table)
						}
						if got := string(smokeIP(t, ctx, family, "-j", "route", "show", "table", table, "exact", prefix)); got != beforeRoute {
							t.Fatalf("foreign preferred-source route changed: before=%s after=%s", beforeRoute, got)
						}
						if got := smokeAddresses(t, ctx, fixture.iface)[source.String()]; !reflect.DeepEqual(got, beforeAddress) {
							t.Fatalf("referenced owned source changed: before=%+v after=%+v", beforeAddress, got)
						}
						fixture.assertForeign(t, ctx)
					}
					t.Logf("%s foreign table %s route and its owned preferred source retained; refusal stable across manager rebuild", family, table)
				})
			}
		}
	})
	t.Run("partial-real-delete-error-and-fresh-manager-retry", func(t *testing.T) {
		fixture := newUpstreamOwnedSmokeFixture(t, ctx, "ownretry")
		manager := newExecUpstreamRouteManager()
		full := fixture.desired()
		ensureUpstreamAfterDAD(t, ctx, manager, fixture, full)
		fixture.assertDesired(t, ctx, full)
		failureFile := filepath.Join(t.TempDir(), "failed-once")
		// Only the test runner injects a failure, after one actual kernel
		// deletion. For ip -batch, feed real lines one at a time until that
		// deletion succeeds, then report exit 42 and leave later work pending.
		manager.runner = func(ctx context.Context, name string, args ...string) *exec.Cmd {
			commandArgs := append([]string{"-c", upstreamDeleteFailureScript, "upstream-delete-failure", name}, args...)
			cmd := exec.CommandContext(ctx, "sh", commandArgs...)
			cmd.Env = append(os.Environ(), "PHOTON_UPSTREAM_FAILURE_FILE="+failureFile)
			return cmd
		}
		if err := manager.EnsureRoutes(ctx, fixture.empty()); err == nil || !strings.Contains(err.Error(), "42") {
			t.Fatalf("partial cleanup error = %v, want visible injected exit 42", err)
		}
		if _, err := os.Stat(failureFile); err != nil {
			t.Fatalf("failure was not injected after a real delete: %v", err)
		}
		remaining := len(fixture.ownedRoutes(t, ctx)) + len(fixture.ownedAddresses(t, ctx))
		if remaining == 0 || remaining >= len(full.Prefixes)+len(full.SourcePrefixes) {
			t.Fatalf("expected a partially completed real cleanup, remaining=%d", remaining)
		}
		fixture.assertForeign(t, ctx)
		manager = newExecUpstreamRouteManager()
		if err := manager.EnsureRoutes(ctx, fixture.empty()); err != nil {
			t.Fatalf("fresh-manager retry: %v", err)
		}
		fixture.assertDesired(t, ctx, fixture.empty())
		t.Log("partial kernel delete error was visible; a fresh manager completed the pending cleanup without touching foreign objects")
	})
}

const upstreamDeleteFailureScript = `
task_delete_failure() {
  if [ ! -e "$PHOTON_UPSTREAM_FAILURE_FILE" ]; then
    : > "$PHOTON_UPSTREAM_FAILURE_FILE"
    echo 'injected error after a real owned delete' >&2
    exit 42
  fi
}
case " $* " in
  *" -batch "*)
    while IFS= read -r task_batch_line; do
      printf '%s\n' "$task_batch_line" | "$@" || exit $?
      case "$task_batch_line" in
        "route del "*|"address del "*|"addr del "*) task_delete_failure ;;
      esac
    done
    ;;
  *" route del "*|*" address del "*|*" addr del "*)
    "$@" || exit $?
    task_delete_failure
    ;;
  *) exec "$@" ;;
esac
`

type upstreamOwnedSmokeFixture struct {
	iface            string
	foreignAddresses []netip.Prefix
	foreignRoutes    []netip.Prefix
	foreignAddrState map[string]smokeAddress
	foreignFIBState  map[string]string
}

func newUpstreamOwnedSmokeFixture(t *testing.T, ctx context.Context, iface string) *upstreamOwnedSmokeFixture {
	t.Helper()
	smokeIP(t, ctx, "link", "add", iface, "type", "veth", "peer", "name", iface+"p")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", iface).Run() })
	for _, dev := range []string{iface, iface + "p"} {
		smokeIP(t, ctx, "link", "set", dev, "addrgenmode", "none")
		smokeIP(t, ctx, "link", "set", dev, "up")
	}
	f := &upstreamOwnedSmokeFixture{iface: iface,
		foreignAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.242/32"), netip.MustParsePrefix("fd42:242:99::1/128"), netip.MustParsePrefix("169.254.242.2/30"), netip.MustParsePrefix("fe80::242:2/64")},
		foreignRoutes:    []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("fd42:242:99:1::/64")},
	}
	for _, address := range f.foreignAddresses {
		family := "-6"
		if address.Addr().Is4() {
			family = "-4"
		}
		smokeIP(t, ctx, family, "addr", "add", address.String(), "dev", iface, "proto", "99")
	}
	for _, prefix := range f.foreignRoutes {
		family := "-6"
		if prefix.Addr().Is4() {
			family = "-4"
		}
		smokeIP(t, ctx, family, "route", "add", prefix.String(), "dev", iface, "proto", "static")
	}
	waitUpstreamDAD(t, ctx, iface, f.foreignAddresses)
	f.foreignAddrState = smokeAddresses(t, ctx, iface)
	f.foreignFIBState = make(map[string]string)
	for _, prefix := range f.foreignRoutes {
		f.foreignFIBState[prefix.String()] = f.routeJSON(t, ctx, prefix)
	}
	t.Cleanup(func() {
		if t.Failed() {
			for _, args := range [][]string{{"-j", "addr", "show", "dev", iface}, {"-4", "-j", "route", "show", "table", "all", "dev", iface}, {"-6", "-j", "route", "show", "table", "all", "dev", iface}} {
				out, err := exec.Command("ip", args...).CombinedOutput()
				t.Logf("failed fixture ip %v (%v): %s", args, err, out)
			}
		}
	})
	return f
}

func (f *upstreamOwnedSmokeFixture) empty() UpstreamRouteSpec {
	return UpstreamRouteSpec{Interface: f.iface, MeshIPv4LL: "169.254.242.1/30", MeshIPv6LL: "fe80::242:1/64"}
}

func (f *upstreamOwnedSmokeFixture) desired() UpstreamRouteSpec {
	spec := f.empty()
	spec.SourcePrefixes = []netip.Prefix{netip.MustParsePrefix("10.242.10.1/32"), netip.MustParsePrefix("10.242.10.2/32"), netip.MustParsePrefix("fd42:242:10::1/128"), netip.MustParsePrefix("fd42:242:10::2/128")}
	spec.Prefixes = []netip.Prefix{netip.MustParsePrefix("198.18.10.0/24"), netip.MustParsePrefix("198.18.11.0/24"), netip.MustParsePrefix("fd42:242:11::/64"), netip.MustParsePrefix("fd42:242:12::/64")}
	return spec
}

type smokeAddress struct {
	Family, Local, Protocol, Scope string
	PrefixLen                      int `json:"prefixlen"`
	Secondary                      bool
	Tentative, DADFailed           bool
}

func waitUpstreamDAD(t *testing.T, ctx context.Context, iface string, prefixes []netip.Prefix) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		addresses := smokeAddresses(t, ctx, iface)
		ready := true
		for _, prefix := range prefixes {
			if !prefix.Addr().Is6() {
				continue
			}
			address, ok := addresses[prefix.String()]
			if !ok || address.DADFailed {
				t.Fatalf("DAD source disappeared or failed: %s: %+v", prefix, addresses)
			}
			ready = ready && !address.Tentative
		}
		if ready {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("IPv6 sources did not finish real DAD in %s", iface)
}

func ensureUpstreamAfterDAD(t *testing.T, ctx context.Context, manager *execUpstreamRouteManager, fixture *upstreamOwnedSmokeFixture, desired UpstreamRouteSpec) {
	t.Helper()
	if err := manager.EnsureRoutes(ctx, desired); err != nil {
		owned := fixture.ownedAddresses(t, ctx)
		tentative := false
		for _, address := range owned {
			tentative = tentative || address.Family == "inet6" && address.Tentative && !address.DADFailed
		}
		if !strings.Contains(err.Error(), "Invalid source address") || !tentative {
			t.Fatalf("unexpected EnsureRoutes failure (not the observed DAD transient): %v; owned=%+v", err, owned)
		}
		// Preserve the real first-call failure and kernel's partial state.
		// This is a later reconcile retry, not a change to DAD or an assertion
		// that the initial call was healthy.
		t.Logf("visible real DAD transient: %v; owned source snapshot=%+v; partial owned routes=%+v", err, owned, fixture.ownedRoutes(t, ctx))
		waitUpstreamDAD(t, ctx, fixture.iface, desired.SourcePrefixes)
		if err := manager.EnsureRoutes(ctx, desired); err != nil {
			t.Fatalf("reconcile retry after actual DAD completion: %v", err)
		}
		t.Log("explicit reconcile retry after real DAD completion succeeded")
	}
}

func smokeAddresses(t *testing.T, ctx context.Context, iface string) map[string]smokeAddress {
	t.Helper()
	var links []struct {
		Addresses []smokeAddress `json:"addr_info"`
	}
	if err := json.Unmarshal(smokeIP(t, ctx, "-j", "addr", "show", "dev", iface), &links); err != nil || len(links) != 1 {
		t.Fatalf("read kernel addresses: %v, %+v", err, links)
	}
	addresses := make(map[string]smokeAddress)
	for _, address := range links[0].Addresses {
		addresses[fmt.Sprintf("%s/%d", address.Local, address.PrefixLen)] = address
	}
	return addresses
}

func smokeProtocol242(protocol string) bool {
	value, err := strconv.ParseUint(protocol, 0, 8)
	return err == nil && value == 242
}

func (f *upstreamOwnedSmokeFixture) ownedAddresses(t *testing.T, ctx context.Context) map[string]smokeAddress {
	addresses := smokeAddresses(t, ctx, f.iface)
	for prefix, address := range addresses {
		if !smokeProtocol242(address.Protocol) {
			delete(addresses, prefix)
		}
	}
	return addresses
}

type smokeRoute struct {
	Dst, Dev, Gateway, Protocol, PrefSrc string
}

func (f *upstreamOwnedSmokeFixture) ownedRoutes(t *testing.T, ctx context.Context) map[string]smokeRoute {
	t.Helper()
	routes := make(map[string]smokeRoute)
	for _, family := range []string{"-4", "-6"} {
		var entries []smokeRoute
		// iproute2 omits "dev" from JSON when a dev filter was supplied.
		// Read the full table so this test verifies the actual interface.
		if err := json.Unmarshal(smokeIP(t, ctx, family, "-j", "route", "show", "table", "main"), &entries); err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if smokeProtocol242(entry.Protocol) && entry.Dev == f.iface {
				routes[entry.Dst] = entry
			}
		}
	}
	return routes
}

func (f *upstreamOwnedSmokeFixture) routeJSON(t *testing.T, ctx context.Context, prefix netip.Prefix) string {
	t.Helper()
	family := "-6"
	if prefix.Addr().Is4() {
		family = "-4"
	}
	return string(smokeIP(t, ctx, family, "-j", "route", "show", "exact", prefix.String()))
}

func (f *upstreamOwnedSmokeFixture) assertForeign(t *testing.T, ctx context.Context) {
	t.Helper()
	addresses := smokeAddresses(t, ctx, f.iface)
	for prefix, before := range f.foreignAddrState {
		if !reflect.DeepEqual(before, addresses[prefix]) {
			t.Fatalf("foreign address %s changed: before=%+v after=%+v", prefix, before, addresses[prefix])
		}
	}
	for _, prefix := range f.foreignRoutes {
		if got := f.routeJSON(t, ctx, prefix); got != f.foreignFIBState[prefix.String()] {
			t.Fatalf("foreign route %s changed: before=%s after=%s", prefix, f.foreignFIBState[prefix.String()], got)
		}
	}
}

func (f *upstreamOwnedSmokeFixture) assertDesired(t *testing.T, ctx context.Context, desired UpstreamRouteSpec) {
	t.Helper()
	addresses, routes := f.ownedAddresses(t, ctx), f.ownedRoutes(t, ctx)
	if len(addresses) != len(desired.SourcePrefixes) || len(routes) != len(desired.Prefixes) {
		t.Fatalf("owned kernel set differs from desired: addresses=%+v routes=%+v desired=%+v", addresses, routes, desired)
	}
	firstSource := map[bool]string{}
	for _, prefix := range desired.SourcePrefixes {
		if _, ok := addresses[prefix.String()]; !ok {
			t.Fatalf("missing owned source %s", prefix)
		}
		is4 := prefix.Addr().Is4()
		if firstSource[is4] == "" || prefix.Addr().Less(netip.MustParseAddr(firstSource[is4])) {
			firstSource[is4] = prefix.Addr().String()
		}
	}
	for _, prefix := range desired.Prefixes {
		route, ok := routes[prefix.String()]
		gateway := "fe80::242:1"
		if prefix.Addr().Is4() {
			gateway = "169.254.242.1"
		}
		if !ok || route.Dev != f.iface || route.Gateway != gateway || route.PrefSrc != firstSource[prefix.Addr().Is4()] {
			t.Fatalf("owned route %s did not converge: %+v", prefix, route)
		}
	}
	f.assertForeign(t, ctx)
}

func smokeIP(t *testing.T, ctx context.Context, args ...string) []byte {
	t.Helper()
	out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %v: %v: %s", args, err, out)
	}
	return out
}
