package inspect

import (
	"github.com/HiggsNet/photon/pkg/routing"
	"net/netip"
	"reflect"
	"testing"
)

func TestSortRouteShowRowsUsesPrefixBeforeZone(t *testing.T) {
	rows := []RouteShowRow{
		{Zone: "a.example.", Prefix: "2001:db8:2::/64", Key: "z"},
		{Zone: "z.example.", Prefix: "10.0.0.0/8", Key: "z"},
		{Zone: "c.example.", Prefix: "2.0.0.0/8", Key: "z"},
		{Zone: "b.example.", Prefix: "2001:db8:1::/64", Key: "z"},
		{Zone: "a.example.", Prefix: "10.0.0.0/8", Key: "a"},
	}
	sortRouteShowRows(rows)
	want := []RouteShowRow{
		{Zone: "c.example.", Prefix: "2.0.0.0/8", Key: "z"},
		{Zone: "a.example.", Prefix: "10.0.0.0/8", Key: "a"},
		{Zone: "z.example.", Prefix: "10.0.0.0/8", Key: "z"},
		{Zone: "b.example.", Prefix: "2001:db8:1::/64", Key: "z"},
		{Zone: "a.example.", Prefix: "2001:db8:2::/64", Key: "z"},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %+v, want prefix-first %+v", rows, want)
	}
}

func TestRouteUsesSharedAssignment(t *testing.T) {
	ars := &routing.AuthorizedRouteSet{AllAssignments: []*routing.AssignmentEntry{
		{
			Prefix:     netip.MustParsePrefix("10.0.9.0/24"),
			Source:     "catofes.",
			AssignedTo: "node-a.catofes.",
			Shared:     true,
		},
	}}
	if !routeUsesSharedAssignment(ars, "node-a.catofes.", "10.0.9.0/24") {
		t.Fatal("shared assignment was not detected")
	}
	if routeUsesSharedAssignment(ars, "node-b.catofes.", "10.0.9.0/24") {
		t.Fatal("assignment for another node was detected as shared")
	}
}
