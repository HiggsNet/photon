package text

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecthttp "github.com/HiggsNet/photon/internal/inspect/http"
	"github.com/HiggsNet/photon/pkg/routing/bird"
)

func TestWriteRoutesDebugShowsBirdAuthorizedCrossView(t *testing.T) {
	dump := &inspecthttp.RoutesResponse{
		LocalZone: "node-a.catofes.",
		ExportSet: []string{"10.0.0.0/24"},
		Authorized: map[string][]string{
			"node-a.catofes.": {"10.0.0.0/24"},
			"node-b.catofes.": {"10.1.0.0/24"},
		},
		Assignments: map[string]inspecthttp.RouteAssignment{
			"10.0.0.0/16": {Source: "catofes.", AssignedTo: "node-a.catofes."},
			"10.1.0.0/16": {Source: "catofes.", AssignedTo: "node-b.catofes."},
		},
	}
	dump.BIRD = []inspecthttp.BirdRoutesView{{
		NetNS:      "photontesth2",
		InstanceID: "main",
		State:      "running",
		Failure:    inspect.BuildFailure(inspect.FailureCodeBirdQuery, errors.New("bird query timed out")),
		Routes: inspecthttp.BuildBirdRouteViews(dump, []bird.BirdRoute{
			{
				Prefix:   netip.MustParsePrefix("10.1.0.0/24"),
				Protocol: "babel1",
				Iface:    "phx-node-b",
				Metric:   96,
				Selected: true,
			},
			{
				Prefix:   netip.MustParsePrefix("10.2.0.0/24"),
				Protocol: "babel1",
				Iface:    "phx-node-c",
				Metric:   128,
				Selected: true,
			},
		}),
	}}

	var buf strings.Builder
	if err := WriteRoutesDebug(&buf, dump); err != nil {
		t.Fatalf("WriteRoutesDebug: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"route_source: gossip_announcements_and_ipam_authorization",
		"bird_cross_view: 1 instances",
		"netns photontesth2",
		"failure: code=bird_query_failed message=bird query timed out",
		"10.1.0.0/24 selected=true authorized=true import_allowed=true zones=node-b.catofes. protocol=babel1 iface=phx-node-b metric=96",
		"10.2.0.0/24 selected=true authorized=false import_allowed=false protocol=babel1 iface=phx-node-c metric=128",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}
}

func TestWriteRouteDebugShowsPrefixExplanationAndBirdMatch(t *testing.T) {
	dump := &inspecthttp.RoutesResponse{
		LocalZone: "node-a.catofes.",
		ExportSet: []string{"10.1.0.0/24"},
		Authorized: map[string][]string{
			"node-b.catofes.": {"10.1.0.0/24"},
		},
		Assignments: map[string]inspecthttp.RouteAssignment{
			"10.1.0.0/16": {Source: "catofes.", AssignedTo: "node-b.catofes."},
		},
		BIRD: []inspecthttp.BirdRoutesView{{
			NetNS:      "photontesth2",
			InstanceID: "main",
			Routes: []inspecthttp.BirdRouteView{{
				Prefix:        "10.1.0.0/24",
				Protocol:      "babel1",
				Iface:         "phx-node-b",
				Metric:        96,
				Selected:      true,
				Authorized:    true,
				ImportAllowed: true,
			}},
		}},
	}

	var buf strings.Builder
	if err := WriteRouteDebug(&buf, netip.MustParsePrefix("10.1.0.0/24"), dump); err != nil {
		t.Fatalf("WriteRouteDebug: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"route_source: gossip_announcements_and_ipam_authorization",
		"prefix: 10.1.0.0/24",
		"local_export: true",
		"authorized: true",
		"announcing_zones: node-b.catofes.",
		"assignment_assigned_to: node-b.catofes.",
		"bird_cross_view: 1",
		"netns=photontesth2 instance=main selected=true authorized=true import_allowed=true protocol=babel1 iface=phx-node-b metric=96",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}
}
