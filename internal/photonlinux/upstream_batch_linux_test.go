package photonlinux

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"syscall"
	"testing"
)

// Run with PHOTON_RUN_NETNS_TESTS=1 inside unshare -Urn. Both cases execute
// the same 26 routes plus source address against a real isolated kernel.
func BenchmarkUpstreamRouteExec(b *testing.B) {
	if os.Getenv("PHOTON_RUN_NETNS_TESTS") != "1" {
		b.Skip("requires isolated kernel namespace")
	}
	currentNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		b.Fatal(err)
	}
	if hostNS := os.Getenv("PHOTON_UPSTREAM_HOST_NETNS"); hostNS == "" || currentNS == hostNS {
		b.Fatal("benchmark requires an isolated network namespace")
	}
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		b.Fatalf("setup: %v: %s", err, out)
	}
	spec := UpstreamRouteSpec{Interface: "lo", SourcePrefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::1/128")}}
	for i := range 26 {
		spec.Prefixes = append(spec.Prefixes, netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::/64", i+1)))
	}
	manager := newExecUpstreamRouteManager()
	cases := []struct {
		name string
		run  func() error
	}{
		{"per_command", func() error {
			// The pre-optimization host-netns path starts a separate ip for
			// each source address and route, stopping on the first error.
			prefixes := append([]netip.Prefix(nil), spec.Prefixes...)
			sort.Slice(prefixes, func(i, j int) bool { return prefixLess(prefixes[i], prefixes[j]) })
			if _, err := exec.Command("ip", "-6", "addr", "replace", "2001:db8::1/128", "dev", "lo").CombinedOutput(); err != nil {
				return err
			}
			for _, prefix := range prefixes {
				if _, err := exec.Command("ip", "-6", "route", "replace", prefix.String(), "dev", "lo", "proto", "static", "src", "2001:db8::1").CombinedOutput(); err != nil {
					return err
				}
			}
			return nil
		}},
		{"batch", func() error { return manager.EnsureRoutes(context.Background(), spec) }},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			var childBefore, childAfter, selfBefore, selfAfter syscall.Rusage
			read := func(who int, usage *syscall.Rusage) {
				if err := syscall.Getrusage(who, usage); err != nil {
					b.Fatal(err)
				}
			}
			read(syscall.RUSAGE_CHILDREN, &childBefore)
			read(syscall.RUSAGE_SELF, &selfBefore)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := tc.run(); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			read(syscall.RUSAGE_SELF, &selfAfter)
			read(syscall.RUSAGE_CHILDREN, &childAfter)
			cpu := func(usage syscall.Rusage) int64 { return usage.Utime.Nano() + usage.Stime.Nano() }
			b.ReportMetric(float64(cpu(childAfter)-cpu(childBefore))/float64(b.N), "child-ns/op")
			b.ReportMetric(float64(cpu(selfAfter)-cpu(selfBefore))/float64(b.N), "self-ns/op")
		})
	}
}
