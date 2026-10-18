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

func TestUpstreamRouteBatchMixedFamiliesAndFailure(t *testing.T) {
	for _, ns := range []string{"", "host", "mesh"} {
		for _, failAt := range []int{0, 2} {
			t.Run(fmt.Sprintf("netns=%s/fail=%d", ns, failAt), func(t *testing.T) {
				f := newUpstreamFake(t)
				f.failWriteAt = failAt
				err := f.manager().EnsureRoutes(context.Background(), UpstreamRouteSpec{NetNS: ns, Interface: f.iface, MeshIPv4LL: "169.254.0.1/30", MeshIPv6LL: "fe80::1/64",
					SourcePrefixes: prefixList("2001:db8::1/128", "192.0.2.1/32"), Prefixes: prefixList("2001:db8:2::/64", "198.51.100.0/24")})
				f.flush()
				want := 4
				if failAt != 0 {
					want = failAt
				}
				if f.writeCalls != want {
					t.Fatalf("mutation processes = %d, want %d", f.writeCalls, want)
				}
				if failAt == 0 && err != nil || failAt != 0 && (err == nil || !strings.Contains(err.Error(), "injected backend failure")) {
					t.Fatalf("batch error = %v", err)
				}
				bodies := []string{"addr add 192.0.2.1/32 dev upstream noprefixroute proto 242\n", "addr add 2001:db8::1/128 dev upstream noprefixroute proto 242\n",
					"route add 198.51.100.0/24 table main dev upstream proto 242 via 169.254.0.1 src 192.0.2.1 metric 0\n",
					"route add 2001:db8:2::/64 table main dev upstream proto 242 via fe80::1 src 2001:db8::1 metric 1024\n"}
				writes := 0
				for i, call := range f.calls {
					if !strings.Contains(strings.Join(call, " "), "-batch") {
						continue
					}
					family := "-4"
					if writes%2 == 1 {
						family = "-6"
					}
					command := []string{"ip", family, "-batch", "-"}
					if ns == "mesh" {
						command = append([]string{"ip", "netns", "exec", ns}, command...)
					}
					if !reflect.DeepEqual(call, command) {
						t.Fatalf("command = %q, want %q", call, command)
					}
					body, e := os.ReadFile(filepath.Join(f.dir, fmt.Sprint(i+1)))
					if e != nil || string(body) != bodies[writes] {
						t.Fatalf("stdin = %q %v, want %q", body, e, bodies[writes])
					}
					writes++
				}
			})
		}
	}
}

func TestUpstreamRouteBatchCombinesIPv6AndPreservesLiteralNames(t *testing.T) {
	for _, iface := range []string{"upstream", "up#1", "up\"1", "up'1", "up\\1", "up\nroute show", "up\x00suffix"} {
		t.Run(iface, func(t *testing.T) {
			f := newUpstreamFake(t)
			f.iface = iface
			spec := UpstreamRouteSpec{Interface: iface, SourcePrefixes: prefixList("2001:db8::1/128")}
			for i := range 26 {
				spec.Prefixes = append(spec.Prefixes, netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::/64", i+1)))
			}
			err := f.manager().EnsureRoutes(context.Background(), spec)
			if strings.ContainsRune(iface, '\x00') {
				if err == nil || len(f.calls) != 0 {
					t.Fatal("NUL interface must fail before execution")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			f.flush()
			want := 2
			if iface != "upstream" {
				want = 27
			}
			if f.writeCalls != want {
				t.Fatalf("mutation processes=%d, want %d", f.writeCalls, want)
			}
			if iface != "upstream" {
				for _, mutation := range f.mutations {
					found := false
					for i, arg := range mutation {
						if arg == "dev" && i+1 < len(mutation) && mutation[i+1] == iface {
							found = true
						}
					}
					if !found {
						t.Fatalf("interface was not passed literally: %q", mutation)
					}
				}
			}
		})
	}
}

// The opt-in parent runs the helper inside an isolated user/network namespace;
// no route or address from this test can reach the host network namespace.
func TestUpstreamRouteBatchNetNS(t *testing.T) {
	if os.Getenv("PHOTON_UPSTREAM_NETNS_HELPER") != "1" {
		if os.Getenv("PHOTON_RUN_NETNS_TESTS") != "1" {
			t.Skip("set PHOTON_RUN_NETNS_TESTS=1 for isolated kernel acceptance")
		}
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run=^TestUpstreamRouteBatchNetNS$", "-test.v")
		hostNS, err := os.Readlink("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		cmd.Env = append(os.Environ(), "PHOTON_UPSTREAM_NETNS_HELPER=1", "PHOTON_UPSTREAM_HOST_NETNS="+hostNS)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated kernel test: %v\n%s", err, out)
		}
		return
	}
	currentNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if hostNS := os.Getenv("PHOTON_UPSTREAM_HOST_NETNS"); hostNS == "" || currentNS == hostNS {
		t.Fatal("kernel acceptance requires an isolated network namespace")
	}
	ip := func(args ...string) []byte {
		t.Helper()
		out, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
		return out
	}
	ip("link", "set", "lo", "up")
	m := newExecUpstreamRouteManager()
	spec := UpstreamRouteSpec{Interface: "lo", SourcePrefixes: prefixList("192.0.2.1/32", "2001:db8::1/128"), Prefixes: prefixList("198.51.100.0/24", "2001:db8:2::/64")}
	for range 2 {
		if err := m.EnsureRoutes(context.Background(), spec); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ family, prefix, source string }{{"-4", "198.51.100.0/24", "192.0.2.1"}, {"-6", "2001:db8:2::/64", "2001:db8::1"}} {
		var routes []struct {
			Dst, Dev, PrefSrc string
			Protocol          json.RawMessage
		}
		if err := json.Unmarshal(ip(tc.family, "-j", "-N", "route", "show", "exact", tc.prefix), &routes); err != nil {
			t.Fatal(err)
		}
		if len(routes) != 1 {
			t.Fatalf("installed route = %+v", routes)
		}
		proto, err := upstreamNumber(routes[0].Protocol, 0)
		if err != nil || routes[0].Dst != tc.prefix || routes[0].Dev != "lo" || proto != 242 || routes[0].PrefSrc != tc.source {
			t.Fatalf("installed route = %+v", routes)
		}
	}
	// A malformed second prefix rejects the whole intention before any write.
	bad := UpstreamRouteSpec{Interface: "lo", Prefixes: prefixList("203.0.112.0/24", "203.0.112.1/24", "203.0.113.0/24")}
	if err := m.EnsureRoutes(context.Background(), bad); err == nil {
		t.Fatal("invalid second prefix was accepted")
	}
	for _, prefix := range []string{"203.0.112.0/24", "203.0.113.0/24"} {
		if got := strings.TrimSpace(string(ip("-4", "-j", "route", "show", "exact", prefix))); got != "[]" {
			t.Fatalf("invalid intention changed kernel routes: %s", got)
		}
	}
}
