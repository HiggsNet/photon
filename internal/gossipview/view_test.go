package gossipview

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	"github.com/HiggsNet/photon/pkg/core/observability"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestGossipViewUsesCurrentRoundAndKeepsLastSuccess(t *testing.T) {
	now := time.Unix(1700000000, 0)
	const local, remote, first = "local.catofes.", "remote.catofes.", "first.catofes."
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 33434}
	config := corehost.GossipDriverConfig{PeerID: local, MaxDatagramBytes: 4096, Limits: corestate.DefaultSyncLimits(), Discovery: corehost.GossipDiscoveryConfig{
		BootstrapPeers: []string{first},
		Bootstrap:      map[string]*net.UDPAddr{remote: addr},
	}}
	driver := corehost.NewGossipDriver(nil, 1, nil, config)
	defer driver.Stop()
	failure := &corestate.PeerFailure{Code: corestate.PeerFailureTimeout, Message: "catalog timeout"}
	common := corestate.View{
		State: &corestate.VerifiedState{ManagedZone: local, Network: zone.NewNetworkState(), IdentityPrivateKey: []byte("private-key")},
		Gossip: &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{
			remote: {LastSyncUnix: now.Add(-time.Hour).Unix(), LastFailure: failure, BackoffUntilUnix: now.Add(time.Second).Unix()},
			local:  {LastSyncUnix: now.Unix()},
		}},
	}
	common.State.Network.Zones[local] = zone.NewZoneState(local, nil)
	common.State.Network.Zones[local].Records[gossip.EndpointRecordKeyUDP] = &zone.Record{
		Zone: local, Key: gossip.EndpointRecordKeyUDP,
		Value:     []byte(`{"endpoints":[{"address":"198.51.100.1","port":33434}],"ttl_seconds":30}`),
		Timestamp: now.Unix(),
	}
	driver.Observability.Update(remote, now, func(p *observability.PeerDiagnostics) {
		p.ActivePullState = string(gossip.SyncSessionCompleted) // The last phase is only a diagnostic.
		p.ObjectPullStats = &observability.PeerObjectPullStats{Failures: 1, LastFailure: &corestate.PeerFailure{Message: "old TCP error"}}
	})
	view := Live(common, driver, now)
	if view.MaxDatagramBytes != 4096 {
		t.Fatalf("datagram byte limit = %d, want 4096", view.MaxDatagramBytes)
	}
	if view.ManagedZone != local || len(view.LocalEndpoints) != 1 || view.LocalEndpoints[0].Address != "198.51.100.1" {
		t.Fatalf("local publication = %s %+v", view.ManagedZone, view.LocalEndpoints)
	}
	if _, ok := view.Find(local); ok {
		t.Fatal("local endpoint created a neighbor")
	}
	if later := Live(common, driver, now.Add(time.Minute)); len(later.LocalEndpoints) != 0 {
		t.Fatalf("expired local endpoints = %+v", later.LocalEndpoints)
	}
	peer, ok := view.Find(remote)
	if !ok || peer.SyncStatus != "backoff" || peer.LastSyncUnix != now.Add(-time.Hour).Unix() ||
		peer.SelectedAddr != addr.String() || peer.ActivePullState != "completed" || peer.ObjectPullStats.LastFailure.Message != "old TCP error" {
		t.Fatalf("unexpected peer during backoff: %+v", peer)
	}
	if waiting, ok := view.Find(first); !ok || waiting.SyncStatus != "waiting" || len(view.Peers) != 2 {
		t.Fatalf("unexpected bootstrap/local peer projection: %+v", view.Peers)
	}
	if retry, _ := Live(common, driver, now.Add(time.Second)).Find(remote); retry.SyncStatus != "retry_pending" {
		t.Fatalf("expired backoff = %s", retry.SyncStatus)
	}
	driver.Gossip.NewSession(remote)
	if active, _ := Live(common, driver, now).Find(remote); active.SyncStatus != "syncing" || active.LastSyncUnix != peer.LastSyncUnix {
		t.Fatalf("active round lost last success: %+v", active)
	}
	common.Gossip.Peers[remote] = corestate.PeerCheckpoint{LastSyncUnix: now.Unix()}
	driver.Gossip.RemoveSession(remote)
	if matched, _ := Live(common, driver, now).Find(remote); matched.SyncStatus != "synced" || matched.LastFailure != nil {
		t.Fatalf("successful checkpoint without a live round = %+v", matched)
	}
	peer.LastFailure.Message = "caller mutated"
	if failure.Message != "catalog timeout" {
		t.Fatal("query borrowed checkpoint failure")
	}
	data, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	var decoded View
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ManagedZone != local || len(decoded.LocalEndpoints) != 1 || decoded.LocalEndpoints[0] != view.LocalEndpoints[0] {
		t.Fatalf("local endpoint did not survive JSON: %+v", decoded.LocalEndpoints)
	}
	if got, _ := decoded.Find(remote); got.ObjectPullStats.LastFailure.Message != "old TCP error" || got.ActivePullState != "completed" || got.LastSyncUnix != peer.LastSyncUnix {
		t.Fatalf("diagnostics did not survive JSON: %+v", got)
	}
}

func TestGossipViewEvaluatesCatalogAndRevocationAtSampleTime(t *testing.T) {
	now := time.Unix(1700000000, 0)
	const peer = "peer."
	network := zone.NewNetworkState()
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, nil)
	network.Zones[peer] = zone.NewZoneState(peer, nil)
	network.Zones[zone.RootZone].Revocations[peer] = &zone.DelegationRevocation{
		ParentZone: zone.RootZone, ChildZone: peer, RevokedAt: now.Add(time.Second).Unix(),
	}
	common := corestate.View{State: &corestate.VerifiedState{Network: network}}
	config := corehost.GossipDriverConfig{Discovery: corehost.GossipDiscoveryConfig{BootstrapPeers: []string{peer}}}
	before := Build(common, config, "", now)
	after := Build(common, config, "", now.Add(time.Second))
	beforePeer, _ := before.Find(peer)
	afterPeer, _ := after.Find(peer)
	if beforePeer.SyncStatus != "waiting" || afterPeer.SyncStatus != "revoked" || afterPeer.Authorization != "revoked" ||
		before.ZoneCount != 2 || after.ZoneCount != 1 || before.CatalogRoot == after.CatalogRoot {
		t.Fatalf("catalog and revocation disagree: before=%+v after=%+v", before, after)
	}
}
