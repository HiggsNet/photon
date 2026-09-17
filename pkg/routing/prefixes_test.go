package routing

import (
	"net/netip"
	"slices"
	"testing"
)

func TestAutoAnnounceAssignedPrefixesSelectors(t *testing.T) {
	local := netip.MustParsePrefix("10.0.1.0/24")
	shared := netip.MustParsePrefix("10.0.2.0/24")
	ars := &AuthorizedRouteSet{AllAssignments: []*AssignmentEntry{
		{Prefix: shared, AssignedTo: "node-a.catofes.", Shared: true, Tag: "edge"},
		{Prefix: local, AssignedTo: "node-a.catofes."},
		{Prefix: local, AssignedTo: "node-a.catofes."},
		{Prefix: netip.MustParsePrefix("10.0.3.0/24"), AssignedTo: "node-b.catofes.", Tag: "edge"},
		nil,
	}}
	for _, tc := range []struct {
		name      string
		all       bool
		selectors []string
		want      []netip.Prefix
	}{
		{name: "disabled"},
		{name: "all flag", all: true, want: []netip.Prefix{local, shared}},
		{name: "all selector", selectors: []string{"all"}, want: []netip.Prefix{local, shared}},
		{name: "non-shared", selectors: []string{"non-shared"}, want: []netip.Prefix{local}},
		{name: "shared", selectors: []string{"shared"}, want: []netip.Prefix{shared}},
		{name: "tag", selectors: []string{"tag:edge"}, want: []netip.Prefix{shared}},
		{name: "assignment", selectors: []string{"assignment:10.0.1.0/24"}, want: []netip.Prefix{local}},
		{name: "no match", selectors: []string{"tag:unknown"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := AutoAnnounceAssignedPrefixes(ars, "node-a.catofes.", tc.all, tc.selectors)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
	fallback := &AuthorizedRouteSet{Assignments: map[netip.Prefix]*AssignmentEntry{local: {Prefix: local, AssignedTo: "node-a.catofes."}}}
	if got := AutoAnnounceAssignedPrefixes(fallback, "node-a.catofes.", true, nil); !slices.Equal(got, []netip.Prefix{local}) {
		t.Fatalf("legacy assignment fallback = %v", got)
	}
}
