package inspect

import (
	"net/netip"
	"testing"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestBuildRotateDebugBuildsRuntimeAndMatchingSAs(t *testing.T) {
	view := BuildRotateDebug(RotateDebugInput{
		Inspection: LinkInspection{
			LastRunUnix:   1700000000,
			LinkInstances: 2,
			Links: []LinkView{
				{ID: "link-a", PeerZone: "node-a.catofes."},
				{
					ID:              "link-b",
					PeerZone:        "node-b.catofes.",
					LinkID:          "link-b",
					PathKey:         "family:ipv4",
					TransportID:     "ipsec-current",
					ChildSAName:     "ipsec-current-child",
					InterfaceName:   "phxold",
					XFRMIfID:        1001,
					Endpoint:        "198.51.100.10:30002",
					LocalTunnelAddr: "fe80::1%phxold",
					PeerTunnelAddr:  "fe80::2%phxold",
					Rotation: LinkRotation{
						RemoteGeneration:      1,
						StagedGeneration:      2,
						StagedIKEName:         "ipsec-current-r2",
						StagedChildSAName:     "ipsec-current-r2-child",
						StagedInterfaceName:   "phxnew",
						StagedXFRMIfID:        2002,
						StagedLocalTunnelAddr: "fe80::3%phxnew",
						StagedPeerTunnelAddr:  "fe80::4%phxnew",
					},
				},
			},
		},
		PlannedSpecs: map[string]ipsec.TransportLinkSpec{
			"link-b": {
				Generation:    2,
				LinkID:        "link-b",
				TransportID:   "ipsec-current-r2",
				InterfaceName: "phxnew",
				XFRMIfID:      2002,
				ContactPoints: []ipsec.ContactPoint{{
					Address:    "198.51.100.10",
					NATTPort:   30003,
					Generation: 2,
				}},
			},
		},
		LastDesiredCount:  2,
		DesiredPlanSource: "planned",
		Filter:            "node-b",
		StoredLabel:       "stored_sas",
		LiveLabel:         "live_sas",
		ReconcileSAs: []LinkSA{{
			Name:           "ipsec-current",
			ChildSA:        "ipsec-current-child",
			XFRMIfID:       1001,
			RemoteEndpoint: "198.51.100.10:30002",
			Established:    true,
		}},
		LiveSAs: []LinkSA{{
			Name:           "ipsec-current-r2",
			ChildSA:        "ipsec-current-r2-child",
			XFRMIfID:       2002,
			RemoteEndpoint: "198.51.100.10:30003",
			Established:    true,
		}},
	})

	if view.LinkInstances != 2 || view.PlannedDesired != 2 || view.Filter != "node-b" || len(view.Links) != 1 {
		t.Fatalf("rotate view header/filter = %+v", view)
	}
	link := view.Links[0]
	if link.Link.ID != "link-b" || link.Current.RuntimeID != "ipsec-current" || link.Current.Port != "30002" {
		t.Fatalf("current runtime = %+v", link.Current)
	}
	if !link.HasStaged || link.Staged.RuntimeID != "ipsec-current-r2" || link.Staged.Port != "30003" {
		t.Fatalf("staged runtime = has=%v %+v", link.HasStaged, link.Staged)
	}
	if len(link.ReconcileMatchingSAs) != 1 || len(link.LiveMatchingSAs) != 1 {
		t.Fatalf("matching SAs = stored=%+v live=%+v", link.ReconcileMatchingSAs, link.LiveMatchingSAs)
	}
	if link.PortGenerationSummary != "2/1/2" || link.PortSummary != "4500/30003/30002/30003" {
		t.Fatalf("ports = generation=%q summary=%q", link.PortGenerationSummary, link.PortSummary)
	}
}

func TestRotateRuntimeCurrentPrefersActiveRuntimeOverPlannedSpec(t *testing.T) {
	link := LinkView{
		ID:              "link-1",
		LinkID:          "link-1",
		TransportID:     "ipsec-526e55bae2e1-r12",
		IKEName:         "ipsec-f46fb3d71fe8-r13",
		ChildSAName:     "ipsec-f46fb3d71fe8-r13-child",
		InterfaceName:   "phx1be3f390",
		XFRMIfID:        467923856,
		Endpoint:        "123.57.143.66:30002",
		LocalTunnelAddr: "fe80::24c7:24ac:32e9:cd45%phx1be3f390 netns=photontesth2",
		PeerTunnelAddr:  "fe80::abdb:3c51:6e24:8655%phx1be3f390 netns=photontesth2",
		Rotation: LinkRotation{
			RemoteGeneration: 1,
			StagedGeneration: 2,
		},
	}
	spec := &ipsec.TransportLinkSpec{
		Generation:      2,
		TransportID:     "ipsec-f46fb3d71fe8-r2",
		InterfaceName:   "phx28e3c6e5",
		XFRMIfID:        686016229,
		LocalTunnelAddr: netip.MustParseAddr("fe80::5ff8:918b:338e:35e6"),
		PeerTunnelAddr:  netip.MustParseAddr("fe80::ec14:d563:b479:44ed"),
		NetNS:           "photontesth2",
		ContactPoints:   []ipsec.ContactPoint{{Address: "123.57.143.66", NATTPort: 30003, Generation: 2}},
	}

	got := RotateRuntimeCurrent(link, spec)
	if got.RuntimeID != link.IKEName {
		t.Fatalf("current runtime id = %q, want active IKE name %q", got.RuntimeID, link.IKEName)
	}
	if got.Port != "30002" || got.Endpoint != "123.57.143.66:30002" {
		t.Fatalf("current endpoint/port = %q/%q, want active runtime 123.57.143.66:30002/30002", got.Endpoint, got.Port)
	}
	if got.LocalTunnelAddr != link.LocalTunnelAddr || got.PeerTunnelAddr != link.PeerTunnelAddr {
		t.Fatalf("current tunnels = %q/%q, want active runtime tunnels", got.LocalTunnelAddr, got.PeerTunnelAddr)
	}
}

func TestRotateRuntimeStagedUsesPersistedRuntimeAndMatchingSA(t *testing.T) {
	link := LinkView{
		ID:     "link-1",
		LinkID: "link-1",
		Rotation: LinkRotation{
			StagedGeneration:      2,
			StagedIKEName:         "ipsec-f46fb3d71fe8-r2",
			StagedChildSAName:     "ipsec-f46fb3d71fe8-r2-child",
			StagedInterfaceName:   "phx28e3c6e5",
			StagedXFRMIfID:        686016229,
			StagedLocalTunnelAddr: "fe80::5ff8:918b:338e:35e6%phx28e3c6e5 netns=photontesth2",
			StagedPeerTunnelAddr:  "fe80::ec14:d563:b479:44ed%phx28e3c6e5 netns=photontesth2",
		},
	}
	sas := []LinkSA{{
		Name:           "ipsec-f46fb3d71fe8-r2",
		ChildSA:        "ipsec-f46fb3d71fe8-r2-child-24",
		XFRMIfID:       686016229,
		RemoteEndpoint: "123.57.143.66:30003",
		Established:    true,
	}}

	got := RotateRuntimeStaged(link, nil, sas)
	if got.Endpoint != "123.57.143.66:30003" || got.Port != "30003" {
		t.Fatalf("staged endpoint/port = %q/%q, want 123.57.143.66:30003/30003", got.Endpoint, got.Port)
	}
	if got.LocalTunnelAddr != "fe80::5ff8:918b:338e:35e6%phx28e3c6e5 netns=photontesth2" {
		t.Fatalf("local tunnel = %q, want persisted staged local tunnel", got.LocalTunnelAddr)
	}
	if got.PeerTunnelAddr != "fe80::ec14:d563:b479:44ed%phx28e3c6e5 netns=photontesth2" {
		t.Fatalf("peer tunnel = %q, want persisted staged peer tunnel", got.PeerTunnelAddr)
	}
}

func TestRotateSAMatchesCurrentAndStagedRuntime(t *testing.T) {
	link := LinkView{
		ID:          "ipsec-main/node-a.catofes.",
		PathKey:     "family:ipv4",
		TransportID: "ipsec-current",
		XFRMIfID:    1001,
		Rotation: LinkRotation{
			StagedIKEName:  "ipsec-current-r2",
			StagedXFRMIfID: 2002,
		},
	}

	if !RotateSAMatchesLink(link, LinkSA{Name: "ipsec-current", XFRMIfID: 1001}) {
		t.Fatalf("current SA did not match link")
	}
	if !RotateSAMatchesLink(link, LinkSA{Name: "ipsec-current-r2", XFRMIfID: 2002}) {
		t.Fatalf("staged SA did not match link")
	}
	if RotateSAMatchesLink(link, LinkSA{Name: "ipsec-current", XFRMIfID: 1001, RemoteEndpoint: "[2001:db8::20]:4500"}) {
		t.Fatalf("wrong-family SA matched link")
	}
	if RotateSAMatchesLink(link, LinkSA{Name: "ipsec-other", XFRMIfID: 3003}) {
		t.Fatalf("unrelated SA matched link")
	}
}
