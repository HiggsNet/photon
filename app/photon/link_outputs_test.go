package main

import (
	"net/netip"
	"testing"

	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestLinkOutputsProjectIPsecRuntimeWithoutLifecycleState(t *testing.T) {
	links := map[string]linkInstanceState{
		"instance-a": {
			ID:               "instance-a",
			LinkID:           "link-a",
			GroupID:          "blue",
			PeerZone:         "node-b.catofes.",
			TransportKind:    ipsec.ProviderStrongSwan,
			PathKey:          "family:ipv6",
			ActualState:      "up",
			InterfaceName:    "phx0",
			LocalTunnelAddr:  netip.MustParseAddr("fe80::1"),
			PeerTunnelAddr:   netip.MustParseAddr("fe80::2"),
			RemoteGeneration: 3,
			Endpoint:         "198.51.100.2:4500",
			LastTransition:   123,
			Owner:            linkOwnerState{Token: "must-not-leak"},
		},
	}

	got := buildLinkOutputs(links, &ipsecObservationSummary{Desired: []desiredLinkState{{
		InstanceID: "instance-a", LocalTunnelAddr: "fe80::1%phx0 netns=photon",
		PeerTunnelAddr: "fe80::2%phx0 netns=photon",
	}}})
	if len(got) != 1 {
		t.Fatalf("outputs = %d, want 1", len(got))
	}
	link := got[0]
	if link.ID != "link-a" || link.GroupID != "blue" || link.PeerZone != zone.ZonePath("node-b.catofes.") {
		t.Fatalf("identity = %+v", link)
	}
	if link.Provider != ipsec.ProviderStrongSwan || link.RuntimeRole != photonstate.LinkRuntimeActive || link.Generation != 3 {
		t.Fatalf("runtime identity = %+v", link)
	}
	if link.NetNS != "photon" || link.InterfaceName != "phx0" || link.LocalAddr.String() != "fe80::1" || link.PeerAddr.String() != "fe80::2" {
		t.Fatalf("babel-facing scope = %+v", link)
	}
	if link.Readiness.Session != photonstate.LinkReadyReady || link.Readiness.Interface != photonstate.LinkReadyReady || link.Readiness.Routing != photonstate.LinkReadyUnknown || link.Readiness.Health != photonstate.LinkReadyUnknown {
		t.Fatalf("readiness = %+v", link.Readiness)
	}
}

func TestLinkOutputsProjectStagedRuntimeSeparately(t *testing.T) {
	links := map[string]linkInstanceState{
		"link-a": {
			ID:                    "link-a",
			GroupID:               "blue",
			ActualState:           "up",
			InterfaceName:         "phx-old",
			LocalTunnelAddr:       netip.MustParseAddr("fe80::1"),
			PeerTunnelAddr:        netip.MustParseAddr("fe80::2"),
			RemoteGeneration:      1,
			StagedGeneration:      2,
			RotatePhase:           "testing_new",
			StagedInterfaceName:   "phx-new",
			StagedLocalTunnelAddr: netip.MustParseAddr("fe80::3"),
			StagedPeerTunnelAddr:  netip.MustParseAddr("fe80::4"),
			StagedIKEName:         "provider-private-runtime-name",
			StagedChildSAName:     "provider-private-child-name",
		},
	}

	got := buildLinkOutputs(links, nil)
	if len(got) != 2 {
		t.Fatalf("outputs = %+v, want active and staged", got)
	}
	byRole := map[string]photonstate.LinkOutput{}
	for _, link := range got {
		byRole[link.RuntimeRole] = link
	}
	if active := byRole[photonstate.LinkRuntimeActive]; active.ID != "link-a" || active.InterfaceName != "phx-old" || active.Generation != 1 {
		t.Fatalf("active = %+v", active)
	}
	if staged := byRole[photonstate.LinkRuntimeStaged]; staged.ID != "link-a#staged" || staged.InterfaceName != "phx-new" || staged.Generation != 2 || staged.PeerAddr.String() != "fe80::4" {
		t.Fatalf("staged = %+v", staged)
	}
}
