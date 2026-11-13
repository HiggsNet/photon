//go:build linux

package photonlinux

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"testing"
)

// Every mutation in this acceptance test runs in a fresh user/network
// namespace. The child refuses to run against the parent's namespace.
func TestUpstreamOwnedObjectsNetNS(t *testing.T) {
	if os.Getenv("PHOTON_UPSTREAM_NETNS_HELPER") != "1" {
		if os.Getenv("PHOTON_RUN_NETNS_TESTS") != "1" {
			t.Skip("set PHOTON_RUN_NETNS_TESTS=1 for isolated kernel acceptance")
		}
		hostNS, err := os.Readlink("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run=^TestUpstreamOwnedObjectsNetNS$", "-test.v")
		cmd.Env = append(os.Environ(), "PHOTON_UPSTREAM_NETNS_HELPER=1", "PHOTON_UPSTREAM_HOST_NETNS="+hostNS)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated kernel test: %v\n%s", err, out)
		}
		return
	}
	currentNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil || currentNS == os.Getenv("PHOTON_UPSTREAM_HOST_NETNS") || os.Getenv("PHOTON_UPSTREAM_HOST_NETNS") == "" {
		t.Fatal("kernel acceptance requires an isolated network namespace")
	}
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}
	ip("link", "set", "lo", "up")
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/lo/promote_secondaries", []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec := UpstreamRouteSpec{Interface: "lo", SourcePrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24"), netip.MustParsePrefix("2001:db8::1/64")}, Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8:2::/64")}}
	read := func(spec UpstreamRouteSpec) upstreamSnapshot {
		t.Helper()
		var snapshot upstreamSnapshot
		if err := withUpstreamRouteIO(t.Context(), spec, func(io upstreamRouteIO) error { var err error; snapshot, err = io.Read(t.Context()); return err }); err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	ensure := func(spec UpstreamRouteSpec) {
		t.Helper()
		// A fresh manager each time exercises restart recovery from the kernel.
		if err := newUpstreamRouteManager().EnsureRoutes(t.Context(), spec); err != nil {
			t.Fatal(err)
		}
	}
	ensure(spec)
	desired, err := desiredUpstreamState(spec)
	if err != nil {
		t.Fatal(err)
	}
	installed := read(spec)
	for _, address := range desired.Addresses {
		if !slices.Contains(installed.Addresses, address) {
			t.Fatalf("marked source missing: %+v", installed)
		}
	}
	for _, route := range desired.Routes {
		if !slices.Contains(installed.Routes, route) {
			t.Fatalf("marked route missing: %+v", installed)
		}
	}
	ensure(spec)
	if !reflect.DeepEqual(read(spec), installed) {
		t.Fatal("steady reconcile changed the kernel state")
	}
	// The administrator's secondary IPv4 address must survive removal of
	// the original primary source. Untagged routes and link-local IPs survive.
	ip("addr", "add", "192.0.2.99/24", "dev", "lo")
	ip("-6", "addr", "add", "fe80::123/64", "dev", "lo")
	ip("-4", "route", "add", "10.0.0.0/8", "dev", "lo", "proto", "static")
	spec.SourcePrefixes[0] = netip.MustParsePrefix("192.0.2.1/32")
	ensure(spec)
	if changed := read(spec); !slices.Contains(changed.Addresses, upstreamAddress{Prefix: spec.SourcePrefixes[0], Protocol: upstreamProtocol}) {
		t.Fatalf("source prefix-length change did not settle: %+v", changed)
	}
	ip("link", "add", "other", "type", "dummy")
	ip("link", "set", "other", "up")
	other := UpstreamRouteSpec{Interface: "other", SourcePrefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8:100::1/128")}, Prefixes: []netip.Prefix{netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("2001:db8:101::/64")}}
	ensure(other)
	otherState := read(other)
	spec.SourcePrefixes[0] = netip.MustParsePrefix("192.0.2.2/24")
	ensure(spec)
	changed := read(spec)
	if !slices.Contains(changed.Addresses, upstreamAddress{Prefix: spec.SourcePrefixes[0], Protocol: upstreamProtocol}) || slices.Contains(changed.Addresses, desired.Addresses[0]) {
		t.Fatalf("source replacement did not settle: %+v", changed)
	}
	spec.SourcePrefixes, spec.Prefixes = nil, nil
	ensure(spec)
	remaining := read(spec)
	for _, address := range remaining.Addresses {
		if address.Protocol == upstreamProtocol {
			t.Fatalf("withdraw left owned source: %+v", remaining)
		}
	}
	for _, route := range remaining.Routes {
		if route.Protocol == upstreamProtocol {
			t.Fatalf("withdraw left owned route: %+v", remaining)
		}
	}
	if !slices.ContainsFunc(remaining.Addresses, func(a upstreamAddress) bool { return a.Prefix == netip.MustParsePrefix("192.0.2.99/24") }) || !slices.ContainsFunc(remaining.Addresses, func(a upstreamAddress) bool { return a.Prefix == netip.MustParsePrefix("fe80::123/64") }) || !slices.ContainsFunc(remaining.Routes, func(r upstreamRoute) bool { return r.Prefix == netip.MustParsePrefix("10.0.0.0/8") && r.Protocol == 4 }) {
		t.Fatalf("withdraw removed administrator objects: %+v", remaining)
	}
	if !reflect.DeepEqual(otherState, read(other)) {
		t.Fatal("withdraw modified another interface")
	}
	if value, err := os.ReadFile("/proc/sys/net/ipv4/conf/lo/promote_secondaries"); err != nil || string(value) != "0\n" {
		t.Fatalf("secondary-address policy was not restored: %q, %v", value, err)
	}
	// Exercise the actual veth/gateway path used by static upstreams, with
	// both address families and preferred source selection.
	ip("link", "add", "mesh", "type", "veth", "peer", "name", "upstream")
	for _, iface := range []string{"mesh", "upstream"} {
		ip("link", "set", iface, "up")
	}
	ip("addr", "add", "169.254.1.1/30", "dev", "mesh")
	ip("addr", "add", "169.254.1.2/30", "dev", "upstream")
	ip("-6", "addr", "add", "fe80::1/64", "dev", "mesh")
	ip("-6", "addr", "add", "fe80::2/64", "dev", "upstream")
	veth := UpstreamRouteSpec{Interface: "upstream", MeshIPv4LL: "169.254.1.1/30", MeshIPv6LL: "fe80::1/64", SourcePrefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.1/32"), netip.MustParsePrefix("2001:db8:ee::1/128")}, Prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8:ff::/64")}}
	ensure(veth)
	vethDesired, err := desiredUpstreamState(veth)
	if err != nil {
		t.Fatal(err)
	}
	vethState := read(veth)
	for _, route := range vethDesired.Routes {
		if !slices.Contains(vethState.Routes, route) {
			t.Fatalf("gateway/source route missing: %+v", vethState)
		}
	}
	veth.SourcePrefixes, veth.Prefixes = nil, nil
	ensure(veth)
	if remaining := read(veth); slices.ContainsFunc(remaining.Routes, func(r upstreamRoute) bool { return r.Protocol == upstreamProtocol }) || slices.ContainsFunc(remaining.Addresses, func(a upstreamAddress) bool { return a.Protocol == upstreamProtocol }) {
		t.Fatalf("veth withdrawal left owned objects: %+v", remaining)
	}
	// Cancellation is checked before sending mutations.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := newUpstreamRouteManager().EnsureRoutes(ctx, other); err == nil {
		t.Fatal("canceled reconcile was accepted")
	}
}
