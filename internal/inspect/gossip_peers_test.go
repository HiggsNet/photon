package inspect

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/observability"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestGossipHistoricalPeerReturnsWithPublishedEndpoint(t *testing.T) {
	now := time.Unix(1700000000, 0)
	id := "old.catofes."
	network := zone.NewNetworkState()
	value, err := json.Marshal(gossip.EndpointRecord{TTL: 60, UpdatedAt: now.Unix(), Endpoints: []gossip.EndpointEntry{{Address: "192.0.2.1", Port: 33434, Protocol: "udp", LastObserved: now.Unix()}}})
	if err != nil {
		t.Fatal(err)
	}
	network.Zones[zone.ZonePath(id)] = &zone.ZoneState{Path: zone.ZonePath(id), Records: map[string]*zone.Record{gossip.EndpointRecordKeyUDP: {Zone: zone.ZonePath(id), Key: gossip.EndpointRecordKeyUDP, Value: value, Timestamp: now.Unix()}}}
	common := corestate.View{State: &corestate.VerifiedState{Network: network}, Gossip: &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{id: {LastSyncUnix: now.Add(-7 * 24 * time.Hour).Unix()}}}}
	for _, tc := range []struct {
		at         time.Time
		historical bool
	}{{now, false}, {now.Add(24 * time.Hour), true}} {
		view, ok := BuildGossipPeerDebugView(common, GossipPeersOptions{Now: tc.at}, id)
		if !ok || view.Historical != tc.historical {
			t.Fatalf("at %s historical=%v known=%v", tc.at, view.Historical, ok)
		}
	}
}

func TestBuildGossipPeerDebugViewRejectsUnknownPeer(t *testing.T) {
	common := corestate.View{State: &corestate.VerifiedState{Network: zone.NewNetworkState()}}
	if _, ok := BuildGossipPeerDebugView(common, GossipPeersOptions{}, "ss"); ok {
		t.Fatal("unknown peer produced debug view")
	}
}

func TestGossipPeerHistoricalRetention(t *testing.T) {
	now := time.Unix(1700000000, 0)
	old := now.Add(-48 * time.Hour).Unix()
	for _, tc := range []struct {
		name      string
		peer      corestate.PeerCheckpoint
		bootstrap bool
		cleanup   time.Duration
		want      bool
	}{
		{name: "cleanup boundary", peer: corestate.PeerCheckpoint{LastSyncUnix: old}, want: true},
		{name: "migrated cleanup timestamp", peer: corestate.PeerCheckpoint{ObservedLastSeenUnix: old}, want: true},
		{name: "recent sync", peer: corestate.PeerCheckpoint{LastSyncUnix: now.Unix(), ObservedLastSeenUnix: old}},
		{name: "recent observation", peer: corestate.PeerCheckpoint{LastSyncUnix: old, ObservedLastSeenUnix: now.Unix()}},
		{name: "never seen"},
		{name: "bootstrap", peer: corestate.PeerCheckpoint{LastSyncUnix: old}, bootstrap: true},
		{name: "configured retention", peer: corestate.PeerCheckpoint{LastSyncUnix: old}, cleanup: 72 * time.Hour},
		{name: "expired cached address", peer: corestate.PeerCheckpoint{LastSyncUnix: old, DiscoveredEndpoint: "192.0.2.1:33434", ObservedEndpoint: "192.0.2.1:33434", ObservedUntilUnix: now.Unix()}, want: true},
		{name: "usable observed address", peer: corestate.PeerCheckpoint{LastSyncUnix: old, ObservedEndpoint: "192.0.2.1:33434", ObservedUntilUnix: now.Add(time.Minute).Unix()}},
		{name: "usable grace address", peer: corestate.PeerCheckpoint{LastSyncUnix: old, ObservedGraceEndpoints: []corestate.ObservedGraceEndpoint{{Endpoint: "192.0.2.1:33434", UntilUnix: now.Add(time.Minute).Unix()}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := "old.catofes."
			common := corestate.View{State: &corestate.VerifiedState{Network: zone.NewNetworkState()}, Gossip: &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{id: tc.peer}}}
			options := GossipPeersOptions{Now: now, Lifecycle: PeerLifecycleConfig{CleanupAfter: tc.cleanup}}
			if tc.bootstrap {
				options.Bootstrap = []PeerBootstrap{{PeerID: id}}
			}
			view, ok := BuildGossipPeerDebugView(common, options, id)
			if !ok || view.Historical != tc.want {
				t.Fatalf("historical=%v known=%v, want %v", view.Historical, ok, tc.want)
			}
			if tc.want && view.Status != "offline" {
				t.Fatalf("historical status=%s", view.Status)
			}
			if len(common.Gossip.Peers) != 1 || common.Gossip.Peers[id].LastSyncUnix != tc.peer.LastSyncUnix {
				t.Fatal("projection changed retained checkpoint")
			}
		})
	}
}

func TestBuildGossipPeerViewsProjectOwnersAndLiveDiagnosticsOnce(t *testing.T) {
	now := time.Unix(1700000000, 0)
	peerID := "node-b.catofes."
	common := corestate.View{
		State: &corestate.VerifiedState{ManagedZone: "node-a.catofes.", Network: zone.NewNetworkState()},
		Gossip: &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{
			peerID: {
				LastSyncUnix: now.Unix(), DiscoveredEndpoint: "203.0.113.10:33434",
				ObservedEndpoint: "198.51.100.10:33434", ObservedUntilUnix: now.Add(time.Minute).Unix(),
			},
		}},
	}
	options := GossipPeersOptions{
		LocalPeerID: "node-a.catofes.", Now: now,
		Bootstrap:   []PeerBootstrap{{PeerID: peerID, Addr: "bootstrap.example:33434", ResolvedAddr: "192.0.2.10:33434"}},
		Diagnostics: map[string]observability.PeerDiagnostics{peerID: {HintAccepted: 2, ObservedSource: "reply_route"}},
	}

	debug, ok := BuildGossipPeerDebugView(common, options, peerID)
	if !ok {
		t.Fatal("known peer was not projected")
	}
	if debug.Source != "bootstrap" || debug.ConfiguredAddr != "bootstrap.example:33434" || debug.ResolvedAddr != "203.0.113.10:33434" {
		t.Fatalf("debug identity/endpoints = %#v", debug)
	}
	if debug.SyncFlow.HintAccepted != 2 || debug.ObservedStatus == "-" {
		t.Fatalf("debug runtime diagnostics = %#v", debug)
	}

	peers := BuildGossipPeersView(common, options)
	if len(peers.Peers) != 1 || peers.Peers[0].PeerID != peerID || peers.Peers[0].HintAccepted != 2 {
		t.Fatalf("canonical peers = %#v", peers)
	}
}
