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
				var calls [][]string
				var captures []string
				dir := t.TempDir()
				m := &execUpstreamRouteManager{runner: func(ctx context.Context, name string, args ...string) *exec.Cmd {
					calls = append(calls, append([]string{name}, args...))
					file := filepath.Join(dir, fmt.Sprint(len(calls)))
					captures = append(captures, file)
					code := "0"
					if failAt == len(calls) {
						code = "1"
					}
					cmd := exec.CommandContext(ctx, "sh", "-c", `cat > "$CAPTURE"; printf 'backend detail'; exit "$EXIT_CODE"`)
					cmd.Env = append(os.Environ(), "CAPTURE="+file, "EXIT_CODE="+code)
					return cmd
				}}
				err := m.EnsureRoutes(context.Background(), UpstreamRouteSpec{
					NetNS: ns, Interface: "upstream", MeshIPv4LL: "169.254.0.1/30", MeshIPv6LL: "fe80::1/64",
					SourcePrefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::1/128"), netip.MustParsePrefix("192.0.2.1/32")},
					Prefixes:       []netip.Prefix{netip.MustParsePrefix("2001:db8:2::/64"), netip.MustParsePrefix("198.51.100.0/24")},
				})
				wantCount := 4
				if failAt != 0 {
					wantCount = failAt
				}
				if len(calls) != wantCount {
					t.Fatalf("commands = %v, want %d", calls, wantCount)
				}
				if (failAt == 0 && err != nil) || (failAt != 0 && (err == nil || !strings.Contains(err.Error(), "backend detail"))) {
					t.Fatalf("batch error = %v", err)
				}
				bodies := []string{
					"addr replace 192.0.2.1/32 dev upstream\n",
					"addr replace 2001:db8::1/128 dev upstream\n",
					"route replace 198.51.100.0/24 dev upstream proto static via 169.254.0.1 src 192.0.2.1\n",
					"route replace 2001:db8:2::/64 dev upstream proto static via fe80::1 src 2001:db8::1\n",
				}
				for i, call := range calls {
					family := "-4"
					if i%2 == 1 {
						family = "-6"
					}
					want := []string{"ip", family, "-batch", "-"}
					if ns == "mesh" {
						want = append([]string{"ip", "netns", "exec", ns}, want...)
					}
					if !reflect.DeepEqual(call, want) {
						t.Fatalf("command = %v, want %v", call, want)
					}
					got, err := os.ReadFile(captures[i])
					if err != nil || string(got) != bodies[i] {
						t.Fatalf("stdin = %q, %v, want %q", got, err, bodies[i])
					}
				}
			})
		}
	}
}

func TestUpstreamRouteBatchCombinesIPv6AndPreservesLiteralNames(t *testing.T) {
	for _, iface := range []string{"upstream", "up#1", "up\"1", "up'1", "up\\1", "up\nroute show", "up\x00suffix"} {
		t.Run(iface, func(t *testing.T) {
			var calls [][]string
			m := &execUpstreamRouteManager{runner: func(ctx context.Context, name string, args ...string) *exec.Cmd {
				calls = append(calls, append([]string{name}, args...))
				return exec.CommandContext(ctx, "sh", "-c", "cat >/dev/null")
			}}
			spec := UpstreamRouteSpec{Interface: iface, SourcePrefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::1/128")}}
			for i := range 26 {
				spec.Prefixes = append(spec.Prefixes, netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::/64", i+1)))
			}
			if err := m.EnsureRoutes(context.Background(), spec); err != nil {
				t.Fatal(err)
			}
			want := 1
			if iface != "upstream" {
				want = 27
			}
			if len(calls) != want {
				t.Fatalf("processes = %d, want %d", len(calls), want)
			}
			if iface != "upstream" {
				for _, call := range calls {
					if len(call) < 7 || call[6] != iface || call[2] == "-batch" {
						t.Fatalf("interface was not passed literally: %q", call)
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
	spec := UpstreamRouteSpec{Interface: "lo",
		SourcePrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("2001:db8::1/128")},
		Prefixes:       []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8:2::/64")},
	}
	for range 2 {
		if err := m.EnsureRoutes(context.Background(), spec); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ family, prefix, source string }{
		{"-4", "198.51.100.0/24", "192.0.2.1"}, {"-6", "2001:db8:2::/64", "2001:db8::1"},
	} {
		var routes []struct{ Dst, Dev, Protocol, PrefSrc string }
		if err := json.Unmarshal(ip(tc.family, "-j", "route", "show", "exact", tc.prefix), &routes); err != nil {
			t.Fatal(err)
		}
		if len(routes) != 1 || routes[0].Dst != tc.prefix || routes[0].Dev != "lo" || routes[0].Protocol != "static" || routes[0].PrefSrc != tc.source {
			t.Fatalf("installed route = %+v", routes)
		}
	}
	// A malformed second prefix must stop this batch before its third line.
	bad := UpstreamRouteSpec{Interface: "lo", Prefixes: []netip.Prefix{
		netip.MustParsePrefix("203.0.112.0/24"), netip.MustParsePrefix("203.0.112.1/24"), netip.MustParsePrefix("203.0.113.0/24"),
	}}
	if err := m.EnsureRoutes(context.Background(), bad); err == nil {
		t.Fatal("invalid second line was accepted")
	}
	if got := strings.TrimSpace(string(ip("-4", "-j", "route", "show", "exact", "203.0.113.0/24"))); got != "[]" {
		t.Fatalf("batch continued past failure: %s", got)
	}
	if got := strings.TrimSpace(string(ip("-4", "-j", "route", "show", "exact", "203.0.112.0/24"))); got == "[]" {
		t.Fatal("successful command before failure was lost")
	}
}
