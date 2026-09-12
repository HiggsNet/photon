package main

import (
	"net/netip"
	"testing"

	"github.com/HiggsNet/photon/internal/photonlinux/linkstate"
	pingdebug "github.com/HiggsNet/photon/internal/ping"
	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/health"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// pingDebugTargets builds the health targets for a fixture state with a
// dual-stack non-rotating link to node-b. and a rotating IPv6 link to node-c.
func pingDebugTargets(t *testing.T) []health.ProbeTarget {
	t.Helper()
	managedZone := zone.ZonePath("local.")
	links := map[string]ipsec.LinkInstance{
		"link-b": {ActualState: "up"},
		"link-c": {
			ActualState:           "up",
			InterfaceName:         "phx-old",
			LocalTunnelAddr:       netip.MustParseAddr("fd00::1"),
			PeerTunnelAddr:        netip.MustParseAddr("fd00::2"),
			StagedGeneration:      2,
			RotatePhase:           "testing_new",
			StagedInterfaceName:   "phx-new",
			StagedLocalTunnelAddr: netip.MustParseAddr("fd00::3"),
			StagedPeerTunnelAddr:  netip.MustParseAddr("fd00::4"),
		},
	}
	reconcile := &ipsecObservationSummary{
		Desired: []photonstate.DesiredLinkObservation{
			{InstanceID: "link-b", GroupID: "g", PeerZone: zone.ZonePath("node-b."), LocalTunnelAddr: "10.0.0.1", PeerTunnelAddr: "10.0.0.2"},
			{InstanceID: "link-b", GroupID: "g", PeerZone: zone.ZonePath("node-b."), LocalTunnelAddr: "fd00::1", PeerTunnelAddr: "fd00::2"},
			{InstanceID: "link-c", GroupID: "g", PeerZone: zone.ZonePath("node-c."), LocalTunnelAddr: "fd00::1", PeerTunnelAddr: "fd00::2"},
		},
	}
	return linkstate.HealthTargets(buildLinkOutputs(links, reconcile), string(managedZone))
}

func TestPingDebugTargetsIncludeActiveOldAndStagedRoles(t *testing.T) {
	targets := pingDebugTargets(t)
	if got := len(targets); got != 4 {
		t.Fatalf("fixture targets = %d, want 4", got)
	}
	cSel := pingdebug.SelectTargetsResolved(targets, "node-c.", pingdebug.ResolveOptions(pingdebug.Options{}))
	roles := map[string]bool{}
	for _, sel := range cSel {
		roles[pingdebug.Role(sel)] = true
	}
	if !roles["old"] || !roles["staged"] {
		t.Fatalf("node-c. roles = %v, want old+staged", roles)
	}
}
