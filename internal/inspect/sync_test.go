package inspect

import (
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestBuildSyncStatusDoesNotInventEphemeralDiagnostics(t *testing.T) {
	now := time.Unix(1700000000, 0)
	view := BuildSyncStatus(corestate.View{
		State: &corestate.VerifiedState{Network: &zone.NetworkState{Zones: map[zone.ZonePath]*zone.ZoneState{}}},
		Gossip: &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{
			"node-b.catofes.": {
				LastSyncUnix: now.Unix(), DiscoveredEndpoint: "127.0.0.1:2000",
				ObservedEndpoint:      "127.0.0.1:3000",
				ObservedFirstSeenUnix: now.Unix(), ObservedLastSeenUnix: now.Unix(),
				ObservedUntilUnix: now.Add(time.Hour).Unix(),
			},
		}},
	}, SyncStatusOptions{
		PeerID: "node-a.catofes.", ListenAddr: "127.0.0.1:0",
		Bootstrap:        []PeerBootstrap{{PeerID: "node-b.catofes.", Addr: "127.0.0.1:9999"}},
		MaxDatagramBytes: 4096, MaxSyncZones: 8, MaxSyncRecords: 64,
		Now: now, Verbose: true,
	})

	if len(view.Bootstrap) != 1 {
		t.Fatalf("bootstrap peers = %+v, want one", view.Bootstrap)
	}
	peer := view.Bootstrap[0]
	if peer.PeerID != "node-b.catofes." || peer.ConfiguredAddr != "127.0.0.1:9999" {
		t.Fatalf("bootstrap peer = %+v", peer)
	}
	if peer.SyncFlow.ActivePullState != "" || peer.SyncFlow.HintAccepted != 0 || peer.SyncFlow.HintSuppressed != 0 || peer.SyncFlow.ReadOnlyResponder != 0 ||
		peer.DatagramStats != (PeerDatagramStatsView{}) || peer.ObjectPullStats != (PeerObjectPullStatsView{}) {
		t.Fatalf("checkpoint projection invented ephemeral diagnostics: flow=%+v datagram=%+v object-pull=%+v", peer.SyncFlow, peer.DatagramStats, peer.ObjectPullStats)
	}
}

func TestBuildSyncStatusGroupsZonesByDotAndHyphenSuffix(t *testing.T) {
	network := zone.NewNetworkState()
	for _, path := range []zone.ZonePath{
		"a-sha.catofes.",
		"b-pek.catofes.",
		"a-pek.catofes.",
		"alpha.catofes.",
	} {
		network.Zones[path] = zone.NewZoneState(path, nil)
	}
	view := BuildSyncStatus(corestate.View{State: &corestate.VerifiedState{Network: network}}, SyncStatusOptions{Now: time.Unix(1700000000, 0)})
	want := []string{"alpha.catofes.", "a-pek.catofes.", "b-pek.catofes.", "a-sha.catofes."}
	if len(view.Zones) != len(want) {
		t.Fatalf("zones = %+v, want %d", view.Zones, len(want))
	}
	for i, path := range want {
		if view.Zones[i].Zone != string(path) {
			t.Fatalf("zones[%d] = %q, want %q; all=%+v", i, view.Zones[i].Zone, path, view.Zones)
		}
	}
}
