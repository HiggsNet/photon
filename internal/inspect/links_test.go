package inspect

import (
	"net/netip"
	"testing"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestBuildLinkInstanceFromRuntimeOmitsInvalidAddresses(t *testing.T) {
	got := BuildLinkInstanceFromRuntime(ipsec.LinkInstance{}, LinkRouting{})
	if got.LocalTunnelAddr != "" || got.PeerTunnelAddr != "" ||
		got.StagedLocalTunnelAddr != "" || got.StagedPeerTunnelAddr != "" {
		t.Fatalf("invalid addresses = %q/%q staged %q/%q, want empty", got.LocalTunnelAddr, got.PeerTunnelAddr, got.StagedLocalTunnelAddr, got.StagedPeerTunnelAddr)
	}

	got = BuildLinkInstanceFromRuntime(ipsec.LinkInstance{
		LocalTunnelAddr: netip.MustParseAddr("fd00::1"),
		PeerTunnelAddr:  netip.MustParseAddr("fd00::2"),
	}, LinkRouting{})
	if got.LocalTunnelAddr != "fd00::1" || got.PeerTunnelAddr != "fd00::2" {
		t.Fatalf("valid addresses = %q/%q", got.LocalTunnelAddr, got.PeerTunnelAddr)
	}
}

func TestBuildLinksPrefersPlannedDesiredOverLastSnapshot(t *testing.T) {
	got := BuildLinks(LinkInput{
		Instances: []LinkInstance{{
			ID:          "link-a",
			PeerZone:    "node-b.example.",
			GroupID:     "main",
			ActualState: "up",
			Endpoint:    "198.51.100.1:4500",
		}},
		LastDesired: []DesiredLink{{
			InstanceID:      "link-a",
			DesiredSpecHash: "old",
			Endpoint:        "198.51.100.1:4500",
		}},
		PlannedDesired: []DesiredLink{{
			InstanceID:      "link-a",
			DesiredSpecHash: "new",
			Endpoint:        "198.51.100.2:4500",
			LocalTunnelAddr: "fd00::1",
		}},
		ActualSAs: []LinkSA{{
			Name:        "link-a",
			Established: true,
		}},
		Health: []HealthSample{{
			InstanceID: "link-a",
			State:      "healthy",
		}},
	})

	if got.Summary.PlannedDesired != 1 || got.Summary.LinkInstances != 1 || got.Summary.ActualSAs != 1 {
		t.Fatalf("summary = %+v", got.Summary)
	}
	if len(got.Links) != 1 {
		t.Fatalf("links = %d, want 1", len(got.Links))
	}
	link := got.Links[0]
	if link.Desired == nil || link.Desired.DesiredSpecHash != "new" {
		t.Fatalf("desired = %+v, want planned snapshot", link.Desired)
	}
	if link.Endpoint != "198.51.100.1:4500" {
		t.Fatalf("endpoint = %q, want persisted actual endpoint", link.Endpoint)
	}
	if link.ActualSA == nil || !link.ActualSA.Established {
		t.Fatalf("actual sa = %+v, want established", link.ActualSA)
	}
	if link.Health == nil || link.Health.State != "healthy" {
		t.Fatalf("health = %+v, want healthy", link.Health)
	}
}

func TestBuildLinksShowsMissingPlannedLinksWhenNoInstancesExist(t *testing.T) {
	got := BuildLinks(LinkInput{
		PlannedDesired: []DesiredLink{{
			InstanceID:    "link-b",
			GroupID:       "main",
			PeerZone:      "node-b.example.",
			InterfaceName: "phx0",
			XFRMIfID:      42,
		}},
	})

	if !got.Summary.HasMissingPlanned {
		t.Fatalf("summary = %+v, want missing planned marker", got.Summary)
	}
	if len(got.Links) != 1 {
		t.Fatalf("links = %d, want 1", len(got.Links))
	}
	link := got.Links[0]
	if !link.Missing || link.State != "missing" || link.InterfaceName != "phx0" || link.XFRMIfID != 42 {
		t.Fatalf("link = %+v, want missing planned link", link)
	}
}

func TestBuildLinksMatchesRotatedRuntimeSAByIKEName(t *testing.T) {
	got := BuildLinks(LinkInput{
		Instances: []LinkInstance{{
			ID:          "link-a",
			TransportID: "ipsec-base",
			IKEName:     "ipsec-base-r2",
			ActualState: "up",
		}},
		ActualSAs: []LinkSA{{
			Name:        "ipsec-base-r2",
			ChildSA:     "ipsec-base-r2-child",
			Established: true,
		}},
	})

	if len(got.Links) != 1 {
		t.Fatalf("links = %d, want 1", len(got.Links))
	}
	if got.Links[0].ActualSA == nil || got.Links[0].ActualSA.Name != "ipsec-base-r2" {
		t.Fatalf("actual sa = %+v, want rotated runtime SA", got.Links[0].ActualSA)
	}
	if got.Links[0].IKEName != "ipsec-base-r2" {
		t.Fatalf("ike name = %q, want rotated runtime name", got.Links[0].IKEName)
	}
}

func TestBuildLinksSortsByPeerZoneDescendingBeforeLinkID(t *testing.T) {
	got := BuildLinks(LinkInput{Instances: []LinkInstance{
		{ID: "link-z", PeerZone: "node-a.example."},
		{ID: "link-a", PeerZone: "node-z.example."},
		{ID: "link-b", PeerZone: "node-z.example."},
	}})

	want := []string{"link-a", "link-b", "link-z"}
	if len(got.Links) != len(want) {
		t.Fatalf("links = %d, want %d", len(got.Links), len(want))
	}
	for i, id := range want {
		if got.Links[i].ID != id {
			t.Fatalf("links[%d] = %q, want %q; links=%+v", i, got.Links[i].ID, id, got.Links)
		}
	}
}

func TestFilterLinkViewsMatchesPeerAndRuntimeFields(t *testing.T) {
	links := []LinkView{
		{
			ID:            "ipsec-main/node-a.catofes.",
			PeerZone:      "node-a.catofes.",
			LinkID:        "link-a",
			TransportID:   "ipsec-current",
			InterfaceName: "phx11111111",
		},
		{
			ID:            "ipsec-main/node-b.catofes.",
			PeerZone:      "node-b.catofes.",
			LinkID:        "link-b",
			TransportID:   "ipsec-staged-r2",
			InterfaceName: "phx22222222",
		},
	}

	if got := FilterLinkViews(links, "node-b.catofes."); len(got) != 1 || got[0].PeerZone != "node-b.catofes." {
		t.Fatalf("filter by peer = %+v, want node-b only", got)
	}
	if got := FilterLinkViews(links, "ipsec-staged"); len(got) != 1 || got[0].TransportID != "ipsec-staged-r2" {
		t.Fatalf("filter by runtime = %+v, want staged runtime", got)
	}
	if got := FilterLinkViews(links, "missing"); len(got) != 0 {
		t.Fatalf("filter missing = %+v, want no links", got)
	}
}
