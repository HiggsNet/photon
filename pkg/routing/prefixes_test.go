package routing

import (
	"bytes"
	"encoding/json"
	"github.com/HiggsNet/photon/pkg/core/zone"
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

func TestAutoAnnounceChangesPreservesOwnership(t *testing.T) {
	const local zone.ZonePath = "node-a.catofes."
	network := zone.NewNetworkState()
	network.Zones[local] = zone.NewZoneState(local, nil)
	// Assigned prefixes include an active explicit route and a withdrawn auto route.
	ars := &AuthorizedRouteSet{AllAssignments: []*AssignmentEntry{
		{Prefix: netip.MustParsePrefix("10.0.1.0/24"), AssignedTo: local},
		{Prefix: netip.MustParsePrefix("10.0.2.0/24"), AssignedTo: local},
		{Prefix: netip.MustParsePrefix("10.0.3.0/24"), AssignedTo: local},
	}}
	for _, announcement := range []RouteAnnouncementRecord{
		{Version: 1, Prefix: "10.0.1.0/24", Active: true},
		{Version: 1, Prefix: "10.0.2.0/24", Controller: RouteControllerAuto},
		{Version: 1, Prefix: "10.0.4.0/24", Active: true, Controller: RouteControllerAuto},
		{Version: 1, Prefix: "10.0.5.0/24", Active: true},
		{Version: 1, Prefix: "10.0.6.0/24", Active: true, Controller: "service"},
	} {
		key, err := NormalizeRouteAnnouncementKey(announcement.Prefix)
		if err != nil {
			t.Fatal(err)
		}
		value, err := json.Marshal(announcement)
		if err != nil {
			t.Fatal(err)
		}
		network.Zones[local].Records[key] = &zone.Record{Zone: local, Key: key, Type: RecordTypeRouteAnnouncement, Value: value}
	}
	network.Zones[local].Records[RecordKeyPrefixRoutes+"broken"] = &zone.Record{Type: RecordTypeRouteAnnouncement, Value: []byte("{")}
	before, err := json.Marshal(network)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name               string
		all                bool
		selectors          []string
		announce, withdraw []string
	}{
		{name: "selectors", selectors: []string{"all"}, announce: []string{"10.0.2.0/24", "10.0.3.0/24"}, withdraw: []string{"10.0.4.0/24"}},
		{name: "disabled withdraws auto only", withdraw: []string{"10.0.4.0/24"}},
		{name: "legacy owns every route", all: true, announce: []string{"10.0.2.0/24", "10.0.3.0/24"}, withdraw: []string{"10.0.4.0/24", "10.0.5.0/24"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			announce, withdraw := AutoAnnounceChanges(network, local, ars, tc.all, tc.selectors)
			for i, got := range [][]netip.Prefix{announce, withdraw} {
				want := [][]string{tc.announce, tc.withdraw}[i]
				if len(got) != len(want) {
					t.Fatalf("result %d = %v, want %v", i, got, want)
				}
				for _, prefix := range want {
					if !slices.Contains(got, netip.MustParsePrefix(prefix)) {
						t.Fatalf("result %d missing %s", i, prefix)
					}
				}
			}
		})
	}
	for _, path := range []zone.ZonePath{"", zone.RootZone} {
		if announce, withdraw := AutoAnnounceChanges(network, path, ars, true, nil); len(announce)+len(withdraw) != 0 {
			t.Fatalf("invalid/root zone produced changes: %v %v", announce, withdraw)
		}
	}
	if announce, withdraw := AutoAnnounceChanges(nil, local, ars, true, nil); len(announce)+len(withdraw) != 0 {
		t.Fatal("nil network produced changes")
	}
	after, err := json.Marshal(network)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("planning mutated network")
	}
}
