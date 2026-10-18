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
	"strings"
	"testing"
)

// The fake preserves kernel state independently of manager instances. Commands
// still use real stdin/process execution so batch contents and argv fallback are
// exercised rather than directly calling the reconciliation helpers.
type upstreamFake struct {
	t                                       *testing.T
	dir, iface                              string
	routes, addresses                       []map[string]any
	calls, mutations                        [][]string
	reads, deletes, failDeleteAt, badJSONAt int
	writeCalls, failWriteAt                 int
	dropMarker                              bool
	beforeRead                              func(*upstreamFake)
	pending                                 func()
}

func newUpstreamFake(t *testing.T) *upstreamFake {
	return &upstreamFake{t: t, dir: t.TempDir(), iface: "upstream"}
}
func (f *upstreamFake) flush() {
	if f.pending != nil {
		p := f.pending
		f.pending = nil
		p()
	}
}
func (f *upstreamFake) manager() *execUpstreamRouteManager {
	return &execUpstreamRouteManager{runner: f.run}
}
func (f *upstreamFake) run(ctx context.Context, name string, args ...string) *exec.Cmd {
	f.flush()
	f.calls = append(f.calls, append([]string{name}, args...))
	bare := append([]string(nil), args...)
	if len(bare) > 3 && bare[0] == "netns" {
		bare = bare[4:]
	}
	output, code := "", "0"
	isRead := false
	for _, arg := range bare {
		if arg == "show" {
			isRead = true
		}
	}
	if isRead {
		f.reads++
		if f.beforeRead != nil {
			f.beforeRead(f)
		}
		var value any
		if bare[0] == "-j" {
			value = []any{map[string]any{"ifname": f.iface, "addr_info": f.addresses}}
			if f.addresses == nil {
				value = []any{map[string]any{"ifname": f.iface, "addr_info": []any{}}}
			}
		} else {
			items := []map[string]any{}
			for _, r := range f.routes {
				p, e := upstreamObservedPrefix(r["dst"].(string), bare[0] == "-4")
				if e == nil && p.Addr().Is4() == (bare[0] == "-4") {
					items = append(items, r)
				}
			}
			value = items
		}
		data, _ := json.Marshal(value)
		output = string(data)
		if f.badJSONAt == f.reads {
			output = "{"
		}
	} else {
		f.writeCalls++
		if f.failWriteAt == f.writeCalls {
			code = "1"
			output = "injected backend failure"
		}
		isDelete := len(bare) > 2 && bare[2] == "del"
		if isDelete {
			f.deletes++
			if f.failDeleteAt == f.deletes {
				code = "1"
				output = "injected backend failure"
			}
		}
	}
	capture := filepath.Join(f.dir, fmt.Sprint(len(f.calls)))
	if !isRead && code == "0" {
		f.pending = func() {
			if len(bare) > 1 && bare[1] == "-batch" {
				body, e := os.ReadFile(capture)
				if e != nil {
					f.t.Fatal(e)
				}
				for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
					if line != "" {
						f.apply(append([]string{bare[0]}, strings.Fields(line)...))
					}
				}
			} else {
				f.apply(bare)
			}
		}
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", `cat > "$CAPTURE"; printf '%s' "$OUTPUT"; exit "$CODE"`)
	cmd.Env = append(os.Environ(), "CAPTURE="+capture, "OUTPUT="+output, "CODE="+code)
	return cmd
}
func (f *upstreamFake) apply(args []string) {
	f.mutations = append(f.mutations, append([]string(nil), args...))
	if len(args) < 4 {
		f.t.Fatalf("bad mock command %q", args)
	}
	value := func(key string) string {
		for i, arg := range args {
			if arg == key && i+1 < len(args) {
				return args[i+1]
			}
		}
		return ""
	}
	if args[1] == "addr" {
		p := netip.MustParsePrefix(args[3])
		if args[2] == "del" {
			kept := f.addresses[:0]
			for _, a := range f.addresses {
				if a["local"] != p.Addr().String() || intValue(a["prefixlen"]) != p.Bits() {
					kept = append(kept, a)
				}
			}
			f.addresses = kept
			return
		}
		family := "inet6"
		if p.Addr().Is4() {
			family = "inet"
		}
		a := map[string]any{"family": family, "local": p.Addr().String(), "prefixlen": p.Bits()}
		if !f.dropMarker {
			a["protocol"] = "0xf2"
		}
		for _, old := range f.addresses {
			op := netip.PrefixFrom(netip.MustParseAddr(old["local"].(string)), intValue(old["prefixlen"]))
			if p.Addr().Is4() && op.Masked().Contains(p.Addr()) {
				a["secondary"] = true
			}
		}
		f.addresses = append(f.addresses, a)
		return
	}
	if args[1] != "route" {
		f.t.Fatalf("unsupported mock command %q", args)
	}
	p := netip.MustParsePrefix(args[3])
	if args[2] == "del" {
		kept := f.routes[:0]
		for _, r := range f.routes {
			match := r["dst"] == p.String() && r["dev"] == value("dev") && intValue(r["protocol"]) == 242 && intValueDefault(r["table"], 254) == 254 && intValue(r["metric"]) == intValue(value("metric"))
			if !match {
				kept = append(kept, r)
			}
		}
		f.routes = kept
		return
	}
	r := map[string]any{"dst": p.String(), "dev": value("dev"), "protocol": "242", "table": 254, "metric": intValue(value("metric"))}
	if s := value("src"); s != "" {
		r["prefsrc"] = s
	}
	if g := value("via"); g != "" {
		r["gateway"] = g
	}
	f.routes = append(f.routes, r)
}
func intValue(v any) int { return intValueDefault(v, 0) }
func intValueDefault(v any, d int) int {
	if v == nil {
		return d
	}
	b, _ := json.Marshal(v)
	n, _ := upstreamNumber(b, d)
	return n
}
func prefixList(values ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(values))
	for i, v := range values {
		out[i] = netip.MustParsePrefix(v)
	}
	return out
}
func ownedAddress(prefix string, secondary bool) map[string]any {
	p := netip.MustParsePrefix(prefix)
	family := "inet6"
	if p.Addr().Is4() {
		family = "inet"
	}
	return map[string]any{"family": family, "local": p.Addr().String(), "prefixlen": p.Bits(), "protocol": "0xf2", "secondary": secondary}
}
func fakeRoute(prefix, dev string, proto any, source string, table int) map[string]any {
	p := netip.MustParsePrefix(prefix)
	metric := 0
	if p.Addr().Is6() {
		metric = 1024
	}
	r := map[string]any{"dst": prefix, "dev": dev, "protocol": proto, "metric": metric, "table": table}
	if source != "" {
		r["prefsrc"] = source
	}
	return r
}

func TestUpstreamReconcileRebuildShrinkClearAndBorrow(t *testing.T) {
	f := newUpstreamFake(t)
	foreign := ownedAddress("192.0.2.9/32", false)
	delete(foreign, "protocol")
	f.addresses = append(f.addresses, foreign)
	f.routes = append(f.routes, fakeRoute("169.254.10.0/30", "upstream", "kernel", "", 254), fakeRoute("203.0.113.0/24", "elsewhere", 242, "", 254))
	spec := UpstreamRouteSpec{Interface: f.iface, SourcePrefixes: prefixList("2001:db8::1/128", "192.0.2.9/32"), Prefixes: prefixList("2001:db8:2::/64", "198.51.100.0/24")}
	originalSources := append([]netip.Prefix(nil), spec.SourcePrefixes...)
	originalRoutes := append([]netip.Prefix(nil), spec.Prefixes...)
	if err := f.manager().EnsureRoutes(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	f.flush()
	if !reflect.DeepEqual(spec.SourcePrefixes, originalSources) || !reflect.DeepEqual(spec.Prefixes, originalRoutes) {
		t.Fatal("caller slices changed")
	}
	n := len(f.mutations)
	if err := f.manager().EnsureRoutes(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	f.flush()
	if len(f.mutations) != n {
		t.Fatalf("new manager rewrote converged state: %v", f.mutations[n:])
	}
	spec.Prefixes = prefixList("198.51.100.0/24")
	spec.SourcePrefixes = prefixList("192.0.2.9/32")
	if err := f.manager().EnsureRoutes(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	f.flush()
	if len(f.addresses) != 1 || f.addresses[0]["protocol"] != nil {
		t.Fatalf("borrowed address was claimed: %v", f.addresses)
	}
	if err := f.manager().EnsureRoutes(context.Background(), UpstreamRouteSpec{Interface: f.iface}); err != nil {
		t.Fatal(err)
	}
	f.flush()
	if len(f.routes) != 2 || len(f.addresses) != 1 {
		t.Fatalf("foreign objects were lost or stale objects retained: %+v %+v", f.routes, f.addresses)
	}
}

func TestUpstreamReconcileForeignConflictStillWithdrawsRevokedRoute(t *testing.T) {
	for _, conflict := range []string{"route", "source"} {
		t.Run(conflict, func(t *testing.T) {
			f := newUpstreamFake(t)
			f.routes = []map[string]any{fakeRoute("198.51.100.0/24", f.iface, 242, "", 254)}
			spec := UpstreamRouteSpec{Interface: f.iface, Prefixes: prefixList("203.0.113.0/24")}
			if conflict == "route" {
				f.routes = append(f.routes, fakeRoute("203.0.113.0/24", "foreign", 99, "", 254))
			} else {
				f.addresses = []map[string]any{ownedAddress("192.0.2.1/24", false)}
				spec.SourcePrefixes = prefixList("192.0.2.1/32")
			}
			if err := f.manager().EnsureRoutes(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "conflict") {
				t.Fatalf("conflict = %v", err)
			}
			f.flush()
			for _, r := range f.routes {
				if r["dst"] == "198.51.100.0/24" {
					t.Fatal("revoked route survived unrelated conflict")
				}
			}
			if len(f.mutations) != 1 || f.mutations[0][2] != "del" {
				t.Fatalf("foreign conflict mutated unintended objects: %q", f.mutations)
			}
		})
	}
}

func TestUpstreamReconcileDeleteFailureCanRetryWithNewManager(t *testing.T) {
	f := newUpstreamFake(t)
	f.routes = []map[string]any{fakeRoute("198.51.100.0/24", f.iface, 242, "", 254), fakeRoute("203.0.113.0/24", f.iface, 242, "", 254)}
	f.failDeleteAt = 2
	spec := UpstreamRouteSpec{Interface: f.iface}
	if err := f.manager().EnsureRoutes(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "injected backend failure") {
		t.Fatalf("failure = %v", err)
	}
	f.flush()
	if len(f.routes) != 1 {
		t.Fatalf("partial progress = %v", f.routes)
	}
	if err := f.manager().EnsureRoutes(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	f.flush()
	if len(f.routes) != 0 {
		t.Fatal("retry retained stale route")
	}
}

func TestUpstreamReconcileValidatesEverythingBeforeMutation(t *testing.T) {
	for _, spec := range []UpstreamRouteSpec{
		{Interface: "upstream", Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), {}}},
		{Interface: "upstream", Prefixes: prefixList("198.51.100.1/24")},
		{Interface: "upstream", SourcePrefixes: []netip.Prefix{{}}},
		{Interface: "upstream", MeshIPv4LL: "fe80::1/64"},
		{Interface: "upstream", MeshIPv6LL: "169.254.0.1/30"},
		{Interface: "upstream", SourcePrefixes: prefixList("192.0.2.1/32", "192.0.2.1/24")},
	} {
		f := newUpstreamFake(t)
		if err := f.manager().EnsureRoutes(context.Background(), spec); err == nil {
			t.Fatalf("accepted %+v", spec)
		}
		if len(f.calls) != 0 {
			t.Fatalf("invalid input executed %q", f.calls)
		}
	}
}

func TestUpstreamReconcileMalformedOrChangedObservationsNeverDelete(t *testing.T) {
	for _, read := range []int{1, 2, 3, 4, 5, 6} {
		t.Run(fmt.Sprint(read), func(t *testing.T) {
			f := newUpstreamFake(t)
			f.routes = []map[string]any{fakeRoute("198.51.100.0/24", f.iface, 242, "", 254)}
			f.badJSONAt = read
			if err := f.manager().EnsureRoutes(context.Background(), UpstreamRouteSpec{Interface: f.iface}); err == nil {
				t.Fatal("malformed observation accepted")
			}
			f.flush()
			if len(f.mutations) != 0 {
				t.Fatalf("malformed JSON caused mutation: %q", f.mutations)
			}
		})
	}
	f := newUpstreamFake(t)
	f.routes = []map[string]any{fakeRoute("198.51.100.0/24", f.iface, 242, "", 254)}
	f.beforeRead = func(f *upstreamFake) {
		if f.reads == 4 {
			f.routes[0]["protocol"] = 99
		}
	}
	if err := f.manager().EnsureRoutes(context.Background(), UpstreamRouteSpec{Interface: f.iface}); err != nil {
		t.Fatal(err)
	}
	f.flush()
	if len(f.mutations) != 0 {
		t.Fatalf("relabelled foreign route deleted: %q", f.mutations)
	}
}

func TestUpstreamReconcileIPv4PrimaryGuardAndSecondaryOrdering(t *testing.T) {
	f := newUpstreamFake(t)
	f.addresses = []map[string]any{ownedAddress("192.0.2.1/24", false), ownedAddress("192.0.2.2/24", true)}
	f.addresses[1]["protocol"] = 99
	f.routes = []map[string]any{fakeRoute("198.51.100.0/24", f.iface, 242, "192.0.2.1", 254)}
	if err := f.manager().EnsureRoutes(context.Background(), UpstreamRouteSpec{Interface: f.iface}); err == nil || !strings.Contains(err.Error(), "secondary") {
		t.Fatalf("guard = %v", err)
	}
	f.flush()
	if len(f.addresses) != 2 || len(f.routes) != 0 {
		t.Fatalf("guard should protect sources without blocking route withdrawal: %+v %+v", f.addresses, f.routes)
	}
	f = newUpstreamFake(t)
	f.addresses = []map[string]any{ownedAddress("192.0.2.1/24", false), ownedAddress("192.0.2.2/24", true)}
	if err := f.manager().EnsureRoutes(context.Background(), UpstreamRouteSpec{Interface: f.iface}); err != nil {
		t.Fatal(err)
	}
	f.flush()
	if len(f.addresses) != 0 || len(f.mutations) != 2 || f.mutations[0][3] != "192.0.2.2/24" {
		t.Fatalf("secondary must precede primary: %q %+v", f.mutations, f.addresses)
	}
}

func TestUpstreamReconcileForeignPreferredSourceGuardAllTables(t *testing.T) {
	for _, table := range []int{254, 123} {
		t.Run(fmt.Sprint(table), func(t *testing.T) {
			f := newUpstreamFake(t)
			f.addresses = []map[string]any{ownedAddress("192.0.2.1/32", false)}
			f.routes = []map[string]any{fakeRoute("198.51.100.0/24", "another", 99, "192.0.2.1", table), fakeRoute("203.0.113.0/24", f.iface, 242, "192.0.2.1", 254)}
			if err := f.manager().EnsureRoutes(context.Background(), UpstreamRouteSpec{Interface: f.iface}); err == nil || !strings.Contains(err.Error(), "preferred source") {
				t.Fatalf("guard = %v", err)
			}
			f.flush()
			if len(f.addresses) != 1 || len(f.routes) != 1 || f.routes[0]["dev"] != "another" {
				t.Fatalf("foreign reference changed: %+v %+v", f.routes, f.addresses)
			}
		})
	}
}

func TestUpstreamReconcileMissingIFAProtocolIsStickyAndNeverClaims(t *testing.T) {
	f := newUpstreamFake(t)
	f.dropMarker = true
	m := f.manager()
	spec := UpstreamRouteSpec{Interface: f.iface, SourcePrefixes: prefixList("192.0.2.1/32")}
	if err := m.EnsureRoutes(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "IFA_PROTO") {
		t.Fatalf("capability error = %v", err)
	}
	f.flush()
	count := len(f.mutations)
	if err := m.EnsureRoutes(context.Background(), spec); err == nil {
		t.Fatal("unsupported marker turned green")
	}
	f.flush()
	if len(f.mutations) != count {
		t.Fatal("sticky capability failure mutated objects")
	}
	if err := f.manager().EnsureRoutes(context.Background(), UpstreamRouteSpec{Interface: f.iface}); err != nil {
		t.Fatal(err)
	}
	f.flush()
	if len(f.addresses) != 1 {
		t.Fatal("new manager claimed unmarked address")
	}
}

func TestUpstreamReconcileExactSourceDoesNotHideDifferentMask(t *testing.T) {
	f := newUpstreamFake(t)
	f.addresses = []map[string]any{ownedAddress("192.0.2.1/32", false), ownedAddress("192.0.2.1/24", false)}
	if err := f.manager().EnsureRoutes(context.Background(), UpstreamRouteSpec{Interface: f.iface, SourcePrefixes: prefixList("192.0.2.1/32")}); err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("different mask accepted: %v", err)
	}
}

func TestUpstreamReconcileNumericProtocolsAndForeignComplexScope(t *testing.T) {
	for _, raw := range []string{`242`, `"242"`, `"0xf2"`} {
		if got, err := upstreamNumber(json.RawMessage(raw), 0); err != nil || got != 242 {
			t.Fatalf("protocol %s => %d %v", raw, got, err)
		}
	}
	f := newUpstreamFake(t)
	r := fakeRoute("198.51.100.0/24", "foreign", 242, "", 123)
	r["nexthops"] = []any{map[string]any{"dev": "other"}}
	f.routes = []map[string]any{r}
	if err := f.manager().EnsureRoutes(context.Background(), UpstreamRouteSpec{Interface: f.iface}); err != nil {
		t.Fatalf("foreign complex route blocked unrelated scope: %v", err)
	}
	f.flush()
	if len(f.mutations) != 0 {
		t.Fatal("foreign route mutated")
	}
}

func TestUpstreamReconcileNumericLocalAddressBinding(t *testing.T) {
	for _, value := range []any{"2", 2, "local"} {
		t.Run(fmt.Sprint(value), func(t *testing.T) {
			f := newUpstreamFake(t)
			f.addresses = []map[string]any{ownedAddress("10.242.40.1/32", false)}
			// Exact shape observed on ImmortalWrt using ip -j -N route.
			f.routes = []map[string]any{{"type": value, "dst": "10.242.40.1", "dev": f.iface,
				"table": "255", "protocol": "2", "scope": "254", "prefsrc": "10.242.40.1"}}
			if err := f.manager().EnsureRoutes(context.Background(), UpstreamRouteSpec{Interface: f.iface}); err != nil {
				t.Fatal(err)
			}
			f.flush()
			if len(f.addresses) != 0 || len(f.mutations) != 1 || f.mutations[0][1] != "addr" {
				t.Fatalf("exact kernel binding should allow only address withdrawal: %v %v", f.addresses, f.mutations)
			}
		})
	}
}

func TestUpstreamReconcileChangesOwnedSourceInSafeOrder(t *testing.T) {
	f := newUpstreamFake(t)
	f.addresses = []map[string]any{ownedAddress("192.0.2.1/32", false)}
	old := fakeRoute("198.51.100.0/24", f.iface, 242, "192.0.2.1", 254)
	old["gateway"], old["metric"] = "169.254.10.1", 50
	f.routes = []map[string]any{old}
	spec := UpstreamRouteSpec{Interface: f.iface, MeshIPv4LL: "169.254.10.1/30",
		SourcePrefixes: prefixList("192.0.2.2/32"), Prefixes: prefixList("198.51.100.0/24")}
	if err := f.manager().EnsureRoutes(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	f.flush()
	if len(f.mutations) != 4 {
		t.Fatalf("unexpected plan: %q", f.mutations)
	}
	wantKinds := []string{"addr add", "route del", "route add", "addr del"}
	for i, command := range f.mutations {
		if strings.Join(command[1:3], " ") != wantKinds[i] {
			t.Fatalf("unsafe update order: %q", f.mutations)
		}
	}
	deletion := strings.Join(f.mutations[1], " ")
	for _, selector := range []string{"table main", "dev upstream", "proto 242", "via 169.254.10.1", "src 192.0.2.1", "metric 50"} {
		if !strings.Contains(deletion, selector) {
			t.Fatalf("route deletion omitted exact selector %s: %s", selector, deletion)
		}
	}
	if len(f.addresses) != 1 || f.addresses[0]["local"] != "192.0.2.2" || len(f.routes) != 1 || f.routes[0]["prefsrc"] != "192.0.2.2" {
		t.Fatalf("source update did not converge: %v %v", f.addresses, f.routes)
	}
}

func TestUpstreamReconcileRejectsComplexOwnedRouteWithoutMutating(t *testing.T) {
	f := newUpstreamFake(t)
	route := fakeRoute("198.51.100.0/24", f.iface, 242, "", 254)
	route["nexthops"] = []any{map[string]any{"dev": f.iface}}
	f.routes = []map[string]any{route}
	if err := f.manager().EnsureRoutes(context.Background(), UpstreamRouteSpec{Interface: f.iface}); err == nil || !strings.Contains(err.Error(), "unsupported owned") {
		t.Fatalf("complex route accepted: %v", err)
	}
	f.flush()
	if len(f.mutations) != 0 {
		t.Fatalf("unsupported shape mutated: %q", f.mutations)
	}
}

func TestUpstreamReconcileRechecksCompleteObjectsBeforeDelete(t *testing.T) {
	for _, object := range []string{"route", "address"} {
		t.Run(object, func(t *testing.T) {
			f := newUpstreamFake(t)
			if object == "route" {
				f.routes = []map[string]any{fakeRoute("198.51.100.0/24", f.iface, 242, "", 254)}
				f.beforeRead = func(f *upstreamFake) {
					if f.reads == 4 {
						f.routes[0]["scope"] = "link"
					}
				}
			} else {
				f.addresses = []map[string]any{ownedAddress("192.0.2.1/32", false)}
				f.beforeRead = func(f *upstreamFake) {
					if f.reads == 7 {
						f.addresses[0]["label"] = "new-owner-label"
					}
				}
			}
			if err := f.manager().EnsureRoutes(context.Background(), UpstreamRouteSpec{Interface: f.iface}); err == nil || !strings.Contains(err.Error(), "changed during withdrawal") {
				t.Fatalf("changed %s accepted: %v", object, err)
			}
			f.flush()
			if len(f.mutations) != 0 {
				t.Fatalf("changed complete object deleted: %q", f.mutations)
			}
		})
	}
}

func TestUpstreamReconcileLocalBindingExceptionIsExact(t *testing.T) {
	for _, field := range []string{"table", "type", "protocol", "dev", "dst"} {
		t.Run(field, func(t *testing.T) {
			f := newUpstreamFake(t)
			f.addresses = []map[string]any{ownedAddress("192.0.2.1/32", false)}
			r := map[string]any{"type": "2", "dst": "192.0.2.1", "dev": f.iface, "table": "255", "protocol": "2", "prefsrc": "192.0.2.1"}
			switch field {
			case "table":
				r[field] = 123
			case "type":
				r[field] = "1"
			case "protocol":
				r[field] = 99
			case "dev":
				r[field] = "other"
			case "dst":
				r[field] = "192.0.2.2"
			}
			f.routes = []map[string]any{r}
			if err := f.manager().EnsureRoutes(context.Background(), UpstreamRouteSpec{Interface: f.iface}); err == nil || !strings.Contains(err.Error(), "foreign route") {
				t.Fatalf("overbroad local binding exception: %s: %v", field, err)
			}
			f.flush()
			if len(f.addresses) != 1 || len(f.mutations) != 0 {
				t.Fatalf("foreign route was invalidated: %v %q", f.addresses, f.mutations)
			}
		})
	}
}
