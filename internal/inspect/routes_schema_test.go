package inspect_test

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/routing/bird"
)

func TestRoutesFromAuthorizedSetPreservesObserverSchema(t *testing.T) {
	managed := zone.ZonePath("node-a.catofes.")
	announced := map[zone.ZonePath]map[netip.Prefix]*routing.RouteEntry{
		managed: {
			netip.MustParsePrefix("10.0.1.0/24"): {AssignmentTag: "edge.cn"},
			netip.MustParsePrefix("10.0.0.0/24"): {},
		},
		"node-b.catofes.": {
			netip.MustParsePrefix("10.1.0.0/24"): {},
		},
	}
	ars := &routing.AuthorizedRouteSet{
		Announced: announced,
		Assignments: map[netip.Prefix]*routing.AssignmentEntry{
			netip.MustParsePrefix("10.0.0.0/16"): {
				Source:     "catofes.",
				AssignedTo: managed,
			},
		},
		AllPools: []*routing.PoolEntry{{
			Prefix:      netip.MustParsePrefix("10.0.0.0/8"),
			Source:      ".",
			DelegatedTo: "catofes.",
		}},
		AllAssignments: []*routing.AssignmentEntry{{
			Prefix:     netip.MustParsePrefix("10.0.0.0/16"),
			Source:     "catofes.",
			AssignedTo: managed,
			Tag:        "edge.cn",
		}},
		Errors: []routing.RouteAuthorizationError{{
			Zone:   "node-b.catofes.",
			Prefix: netip.MustParsePrefix("10.2.0.0/24"),
			Code:   "route_unassigned",
			Detail: "not delegated",
		}},
	}

	resp := inspect.RoutesFromAuthorizedSet(managed, ars)
	if resp.LocalZone != managed {
		t.Fatalf("local zone = %s, want %s", resp.LocalZone, managed)
	}
	if got := resp.ExportSet; len(got) != 2 || got[0] != "10.0.0.0/24" || got[1] != "10.0.1.0/24" {
		t.Fatalf("export set = %#v, want prefix sorted values", got)
	}
	if got := resp.Assignments["10.0.0.0/16"]; got.Source != "catofes." || got.AssignedTo != string(managed) {
		t.Fatalf("assignment = %#v", got)
	}
	if len(resp.IPAMPools) != 1 || resp.IPAMPools[0].Prefix != "10.0.0.0/8" || resp.IPAMPools[0].DelegatedTo != "catofes." {
		t.Fatalf("ipam pools = %#v", resp.IPAMPools)
	}
	if len(resp.IPAMAssignments) != 1 || resp.IPAMAssignments[0].Prefix != "10.0.0.0/16" || resp.IPAMAssignments[0].AssignedTo != string(managed) {
		t.Fatalf("ipam assignments = %#v", resp.IPAMAssignments)
	}
	if resp.IPAMAssignments[0].Tag != "edge.cn" {
		t.Fatalf("ipam assignment tag = %q, want edge.cn", resp.IPAMAssignments[0].Tag)
	}
	if len(resp.AuthorizedRoutes) != 3 || resp.AuthorizedRoutes[1].Prefix != "10.0.1.0/24" || resp.AuthorizedRoutes[1].Tag != "edge.cn" {
		t.Fatalf("authorized routes = %#v", resp.AuthorizedRoutes)
	}
	if len(resp.Errors) != 1 || resp.Errors[0].Code != "route_unassigned" || resp.Errors[0].Prefix != "10.2.0.0/24" {
		t.Fatalf("errors = %#v", resp.Errors)
	}

	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"local_zone", "export_set", "authorized", "authorized_routes", "assignments", "ipam_pools", "ipam_assignments", "errors"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("missing JSON key %q in %s", key, raw)
		}
	}
}

func TestRoutesFromAuthorizedSetUsesAllIPAMAssignments(t *testing.T) {
	managed := zone.ZonePath("node-a.catofes.")
	prefix := netip.MustParsePrefix("10.0.0.0/24")
	ars := &routing.AuthorizedRouteSet{
		Announced: map[zone.ZonePath]map[netip.Prefix]*routing.RouteEntry{},
		Assignments: map[netip.Prefix]*routing.AssignmentEntry{
			prefix: {
				Source:     "catofes.",
				AssignedTo: "node-a.catofes.",
				Shared:     true,
			},
		},
		AllAssignments: []*routing.AssignmentEntry{
			{Prefix: prefix, Source: "catofes.", AssignedTo: "node-a.catofes.", Shared: true},
			{Prefix: prefix, Source: "catofes.", AssignedTo: "node-b.catofes.", Shared: true},
		},
	}

	resp := inspect.RoutesFromAuthorizedSet(managed, ars)
	if len(resp.Assignments) != 1 {
		t.Fatalf("legacy assignments len = %d, want representative map entry", len(resp.Assignments))
	}
	if len(resp.IPAMAssignments) != 2 {
		t.Fatalf("ipam assignments len = %d, want all assignments: %#v", len(resp.IPAMAssignments), resp.IPAMAssignments)
	}
	if !resp.IPAMAssignments[0].Shared || !resp.IPAMAssignments[1].Shared {
		t.Fatalf("ipam assignments should preserve shared flag: %#v", resp.IPAMAssignments)
	}
	if resp.IPAMAssignments[0].AssignedTo != "node-a.catofes." || resp.IPAMAssignments[1].AssignedTo != "node-b.catofes." {
		t.Fatalf("ipam assignments order/content = %#v", resp.IPAMAssignments)
	}
}

func TestRoutesFromAuthorizedSetGroupsSharedAuthorizedRoutes(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.9.0/24")
	ars := &routing.AuthorizedRouteSet{Announced: map[zone.ZonePath]map[netip.Prefix]*routing.RouteEntry{
		"node-b.catofes.": {prefix: {SharedAssignment: true}},
		"node-a.catofes.": {prefix: {SharedAssignment: true}},
		"node-c.catofes.": {netip.MustParsePrefix("10.0.8.0/24"): {}},
	}}

	resp := inspect.RoutesFromAuthorizedSet("node-a.catofes.", ars)
	want := []string{"node-a.catofes.", "node-b.catofes."}
	got := resp.SharedAuthorized[prefix.String()]
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("shared authorized = %#v, want %#v", got, want)
	}
	if _, ok := resp.SharedAuthorized["10.0.8.0/24"]; ok {
		t.Fatalf("non-shared route included in shared groups: %#v", resp.SharedAuthorized)
	}
}

func TestBuildBirdRouteViewsAnnotatesAuthorizedAndImportAllowed(t *testing.T) {
	dump := &inspect.RoutesResponse{
		Authorized: map[string][]string{
			"node-a.catofes.": {"10.0.0.0/24"},
			"node-b.catofes.": {"10.0.0.0/24"},
		},
		Assignments: map[string]inspect.RouteAssignment{
			"10.0.0.0/16": {Source: "catofes.", AssignedTo: "node-a.catofes."},
		},
	}

	views := inspect.BuildBirdRouteViews(dump, []bird.BirdRoute{
		{
			Prefix:   netip.MustParsePrefix("10.0.2.0/24"),
			Protocol: "babel",
			Iface:    "phx-b",
			Metric:   128,
			Selected: true,
		},
		{
			Prefix:   netip.MustParsePrefix("10.0.0.0/24"),
			Protocol: "babel",
			Iface:    "phx-a",
			Metric:   96,
			Selected: true,
		},
	})
	if len(views) != 2 {
		t.Fatalf("views len = %d, want 2", len(views))
	}
	if views[0].Prefix != "10.0.0.0/24" || !views[0].Authorized || !views[0].ImportAllowed {
		t.Fatalf("first route view = %#v", views[0])
	}
	if got := views[0].Zones; len(got) != 2 || got[0] != "node-a.catofes." || got[1] != "node-b.catofes." {
		t.Fatalf("zones = %#v, want sorted authorized zones", got)
	}
	if views[1].Prefix != "10.0.2.0/24" || views[1].Authorized || !views[1].ImportAllowed {
		t.Fatalf("second route view = %#v", views[1])
	}
}
