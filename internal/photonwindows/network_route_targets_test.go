package photonwindows

import (
	"net"
	"net/netip"
	"testing"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestNetworkRouteTargetsAreDetachedAndDeterministic(t *testing.T) {
	var targets networkRouteTargets
	if len(targets.load()) != 0 {
		t.Fatal("unexpected initial targets")
	}
	bootstrap := map[string]*net.UDPAddr{"a": {IP: net.ParseIP("192.0.2.1"), Port: 33434}, "nil": nil}
	plan := GatewayPlan{Candidates: []GatewayCandidate{{Contacts: []ipsec.ContactPoint{{Address: "192.0.2.1"}, {Address: "2001:db8::2"}, {Address: "unresolved.example"}}}}}
	targets.update(plan, bootstrap)
	got := targets.load()
	if len(got) != 2 || got[0] != netip.MustParseAddr("192.0.2.1") || got[1] != netip.MustParseAddr("2001:db8::2") {
		t.Fatal(got)
	}
	bootstrap["a"].IP[15] = 5
	plan.Candidates[0].Contacts[0].Address = "192.0.2.99"
	targets.update(GatewayPlan{}, nil)
	if len(targets.load()) != 0 || got[0] != netip.MustParseAddr("192.0.2.1") {
		t.Fatal("published inputs mutated", got)
	}
	inner := networkRouteTargets{splitRoutes: []netip.Prefix{netip.MustParsePrefix("fd42::/16")}}
	inner.update(GatewayPlan{}, nil, netip.MustParseAddr("fd42::1"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("fe80::1"))
	if len(inner.load()) != 1 || inner.load()[0] != netip.MustParseAddr("2001:db8::1") {
		t.Fatal("inner/link-local address included in outer observer", inner.load())
	}
}

func TestOutboundPathsChangedIgnoresTargetChurn(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	c := netip.MustParseAddr("2001:db8::3")
	previous := map[netip.Addr]string{a: "wifi", b: "ethernet"}
	if outboundPathsChanged(previous, map[netip.Addr]string{a: "wifi", c: "wifi"}) {
		t.Fatal("target refresh was treated as a path change")
	}
	if !outboundPathsChanged(previous, map[netip.Addr]string{a: "ethernet", c: "wifi"}) {
		t.Fatal("a retained target changed interfaces without triggering recovery")
	}
	if !outboundPathsChanged(previous, map[netip.Addr]string{a: "unreachable"}) {
		t.Fatal("loss of a retained path was ignored")
	}
}

func TestOutboundRoutePrefersSpecificityThenCombinedMetric(t *testing.T) {
	defaultRoute := outboundRoute{index: 1, luid: 10, prefixBits: 0, metric: 5}
	specific := outboundRoute{index: 2, luid: 20, prefixBits: 24, metric: 500}
	faster := outboundRoute{index: 3, luid: 30, prefixBits: 24, metric: 450}
	if !specific.precedes(defaultRoute) || !faster.precedes(specific) || defaultRoute.precedes(specific) {
		t.Fatal("longest prefix must win before the combined metric")
	}
	faster.metric = specific.metric
	if !specific.precedes(faster) || faster.precedes(specific) {
		t.Fatal("equal routes need a stable tie-break")
	}
}
