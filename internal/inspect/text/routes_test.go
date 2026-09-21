package text

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/routing/bird"
)

func TestWriteRoutesDebugShowsBirdAuthorizedCrossView(t *testing.T) {
	dump := &inspect.RoutesResponse{
		LocalZone: "node-a.catofes.",
		ExportSet: []string{"10.0.0.0/24"},
		Authorized: map[string][]string{
			"node-a.catofes.": {"10.0.0.0/24"},
			"node-b.catofes.": {"10.1.0.0/24"},
		},
		Assignments: map[string]inspect.RouteAssignment{
			"10.0.0.0/16": {Source: "catofes.", AssignedTo: "node-a.catofes."},
			"10.1.0.0/16": {Source: "catofes.", AssignedTo: "node-b.catofes."},
		},
	}
	dump.BIRD = []inspect.BirdRoutesView{{
		NetNS:      "photontesth2",
		InstanceID: "main",
		State:      "running",
		Failure:    inspect.BuildFailure(inspect.FailureCodeBirdQuery, errors.New("bird query timed out")),
		Routes: inspect.BuildBirdRouteViews(dump, []bird.BirdRoute{
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
	dump := &inspect.RoutesResponse{
		LocalZone: "node-a.catofes.",
		ExportSet: []string{"10.1.0.0/24"},
		Authorized: map[string][]string{
			"node-b.catofes.": {"10.1.0.0/24"},
		},
		Assignments: map[string]inspect.RouteAssignment{
			"10.1.0.0/16": {Source: "catofes.", AssignedTo: "node-b.catofes."},
		},
		BIRD: []inspect.BirdRoutesView{{
			NetNS:      "photontesth2",
			InstanceID: "main",
			Routes: []inspect.BirdRouteView{{
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

func TestWriteRouteShowReportUsesFilteredVerboseTable(t *testing.T) {
	report := &inspect.RouteShowReport{
		ManagedZone: "node-a.catofes.",
		Announcements: []inspect.RouteShowRow{
			{
				Zone: "node-a.catofes.", Prefix: "10.0.1.0/24", Tag: "edge.cn", Active: true,
				Authorized: true, Controller: "service", Version: 2,
				Key: "routes/announcements/10.0.1.0_24",
			},
			{Zone: "node-b.catofes.", Prefix: "10.0.2.0/24", Active: false},
		},
	}
	var output bytes.Buffer
	if err := WriteRouteShowReport(&output, report, true, "node-a", true); err != nil {
		t.Fatalf("WriteRouteShowReport: %v", err)
	}
	for _, want := range []string{
		"announcements: 1/2",
		"PREFIX", "ZONE", "TAG", "STATE", "AUTHORIZATION", "CONTROLLER", "VERSION", "RECORD",
		"10.0.1.0/24", "node-a.catofes.", "edge.cn", "active", "authorized", "service",
		"routes/announcements/10.0.1.0_24",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "node-b.catofes.") {
		t.Fatalf("filter leaked node-b:\n%s", output.String())
	}
}

func TestWriteRouteShowReportSeparatesAndGroupsSharedAnnouncements(t *testing.T) {
	report := &inspect.RouteShowReport{
		ManagedZone: "node-a.catofes.",
		Announcements: []inspect.RouteShowRow{
			{Zone: "node-a.catofes.", Prefix: "10.0.1.0/24", Active: true, Authorized: true},
			{Zone: "node-b.catofes.", Prefix: "10.0.9.0/24", Shared: true, Active: true, Authorized: true},
			{Zone: "node-c.catofes.", Prefix: "10.0.9.0/24", Shared: true, Active: true, Authorized: true},
		},
	}
	var output bytes.Buffer
	if err := WriteRouteShowReport(&output, report, false, "", false); err != nil {
		t.Fatalf("WriteRouteShowReport: %v", err)
	}
	got := output.String()
	for _, want := range []string{
		"non_shared_announcements: 1",
		"shared_announcements: 2 (1 prefixes)",
		"node-b.catofes.",
		"node-c.catofes.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
	if count := strings.Count(got, "10.0.9.0/24"); count != 1 {
		t.Fatalf("shared prefix rendered %d times, want once:\n%s", count, got)
	}
}

func TestWriteRouteShowReportRightAlignsZoneColumn(t *testing.T) {
	report := &inspect.RouteShowReport{
		Announcements: []inspect.RouteShowRow{
			{Zone: ".", Prefix: "10.0.0.0/8", Active: true, Authorized: true},
			{Zone: "node-a.catofes.", Prefix: "10.1.0.0/16", Active: true, Authorized: true},
		},
	}
	var output bytes.Buffer
	if err := WriteRouteShowReport(&output, report, false, "", false); err != nil {
		t.Fatalf("WriteRouteShowReport: %v", err)
	}
	lines := strings.Split(output.String(), "\n")
	var shortLine, longLine string
	for _, line := range lines {
		switch {
		case strings.Contains(line, "10.0.0.0/8"):
			shortLine = line
		case strings.Contains(line, "10.1.0.0/16"):
			longLine = line
		}
	}
	shortEnd := strings.LastIndex(shortLine, ".") + 1
	longStart := strings.Index(longLine, "node-a.catofes.")
	longEnd := longStart + len("node-a.catofes.")
	if shortLine == "" || longLine == "" || shortEnd != longEnd {
		t.Fatalf("ZONE cells are not right-aligned (ends %d/%d):\n%s", shortEnd, longEnd, output.String())
	}
}
