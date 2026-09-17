package photonlinux

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/routing"
)

func TestExternalUpstreamSourcePrefixesExcludeSharedAssignments(t *testing.T) {
	local := netip.MustParsePrefix("2a0d:2905:1:7::/64")
	shared := netip.MustParsePrefix("2a0d:2905::/96")
	ars := &routing.AuthorizedRouteSet{
		AllAssignments: []*routing.AssignmentEntry{
			{Prefix: local, AssignedTo: "node-a.catofes."},
			{Prefix: shared, AssignedTo: "node-a.catofes.", Shared: true, Tag: "edge.c"},
		},
	}

	got := ExternalUpstreamSourcePrefixes(ars, "node-a.catofes.")
	want := netip.MustParsePrefix("2a0d:2905:1:7::1/64")
	if len(got) != 1 || got[0] != want {
		t.Fatalf("external source prefixes = %v, want only non-shared source %s", got, want)
	}
}

func TestRoutingExportPolicy(t *testing.T) {
	local := netip.MustParsePrefix("10.0.1.0/24")
	remote := netip.MustParsePrefix("10.0.2.0/24")
	ars := &routing.AuthorizedRouteSet{Announced: map[zone.ZonePath]map[netip.Prefix]*routing.RouteEntry{
		"node-a.catofes.": {local: {}}, "node-b.catofes.": {remote: {}},
	}}
	for _, tc := range []struct {
		name   string
		policy firewall.ForwardingPolicy
		want   []netip.Prefix
	}{
		{name: "absent policy", want: []netip.Prefix{local}},
		{name: "transit", policy: firewall.ForwardingPolicy{Transit: true}, want: []netip.Prefix{local, remote}},
		{name: "allow", policy: firewall.ForwardingPolicy{Transit: true, AllowPrefixes: []netip.Prefix{remote}}, want: []netip.Prefix{remote}},
		{name: "deny wins", policy: firewall.ForwardingPolicy{Transit: true, AllowPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")}, DenyPrefixes: []netip.Prefix{remote}}, want: []netip.Prefix{local}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildRoutingExportSet(ars, "node-a.catofes.", tc.policy)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for _, p := range tc.want {
				if !slices.Contains(got, p) {
					t.Fatalf("missing %s in %v", p, got)
				}
			}
		})
	}
	if got := BuildRoutingExportSet(nil, "node-a.catofes.", firewall.ForwardingPolicy{}); len(got) != 0 {
		t.Fatalf("nil authorization exported %v", got)
	}
}

func TestExternalUpstreamRoutesExcludeLocalSubnets(t *testing.T) {
	local := netip.MustParsePrefix("10.0.1.0/24")
	subnet := netip.MustParsePrefix("10.0.1.0/25")
	aggregate := netip.MustParsePrefix("10.0.0.0/16")
	remote := netip.MustParsePrefix("2001:db8:1::/64")
	ars := &routing.AuthorizedRouteSet{
		AllAssignments: []*routing.AssignmentEntry{{Prefix: local, AssignedTo: "node-a.catofes."}},
		Announced: map[zone.ZonePath]map[netip.Prefix]*routing.RouteEntry{
			"node-a.catofes.": {local: {}, subnet: {}},
			"node-b.catofes.": {aggregate: {}, remote: {}},
			"node-c.catofes.": {remote: {}},
		},
	}
	got := ExternalUpstreamRoutePrefixes(ars, "node-a.catofes.")
	if !slices.Equal(got, []netip.Prefix{aggregate, remote}) {
		t.Fatalf("upstream routes = %v, want aggregate and deduplicated remote", got)
	}
}
