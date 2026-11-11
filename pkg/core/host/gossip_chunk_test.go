package host

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestGossipDriverHandleGossipObjectChunkReturnsCompletion(t *testing.T) {
	now := time.Unix(100, 0)
	view := loadedGossipState("remote.catofes.")
	snapshot, err := corestate.Snapshot(view.State.Network, "remote.catofes.")
	if err != nil {
		t.Fatal(err)
	}
	chunks, err := gossip.BuildZoneSnapshotChunks(snapshot, gossip.DefaultDatagramBudget, "sender.catofes.", []byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	driver := NewGossipDriver(nil, 4, &memoryGossipStateStore{views: []corestate.View{view}}, GossipDriverConfig{})
	defer driver.Stop()
	var completed *gossip.ObjectChunkEvent
	for index, chunk := range chunks {
		event, err := driver.HandleGossipObjectChunk(&gossip.Message{PeerID: "peer-a", ObjectChunk: chunk}, now)
		if err != nil {
			t.Fatal(err)
		}
		if index < len(chunks)-1 && event != nil {
			t.Fatalf("chunk %d completed early", index)
		}
		completed = event
	}
	if completed == nil || completed.Snapshot == nil || completed.Snapshot.Zone != snapshot.Zone {
		t.Fatalf("completion event = %#v", completed)
	}
}

func TestGossipDriverOnlyDecodesRequestedChunks(t *testing.T) {
	now := time.Unix(100, 0)
	store := &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}}
	driver := NewGossipDriver(nil, 2, store, GossipDriverConfig{})
	defer driver.Stop()
	data := []byte("invalid snapshot")
	hash := sha256.Sum256(data)
	chunk := &gossip.ObjectChunk{
		TransferID: []byte("0123456789abcdef"), Object: gossip.ObjectPullZone,
		Zone: "remote.catofes.", RootHash: []byte("advertised-root"), ObjectHash: hash[:], Index: 0, Total: 1, Data: data,
	}
	var logs []capturedGossipLog
	driver.gossipConfig.Log = gossipLogCapture(func(record capturedGossipLog) {
		if record.Level == "warn" {
			logs = append(logs, record)
		}
	})
	bindMemoryGossipTransport(t, driver, "peer-a")
	session := driver.Gossip.NewSession("peer-a")
	packet := GossipPacketReceived{Packet: &gossip.Packet{Message: &gossip.Message{
		Type: gossip.MessageObjectChunk, PeerID: "peer-a", ObjectChunk: chunk,
	}}}
	if _, err := driver.HandleGossipHostEvent(t.Context(), packet, now); err != nil || len(logs) != 0 || len(store.updates) != 0 {
		t.Fatalf("unsolicited chunk produced work: error=%v logs=%v updates=%v", err, logs, store.updates)
	}
	_, _ = session.OnEvent(&gossip.SyncTimerEvent{PeerID: "peer-a"}, now)
	_, _ = session.OnEvent(&gossip.CatalogPageReceivedEvent{PeerID: "peer-a", Page: &corestate.CatalogPage{Entries: []corestate.ZoneDigest{{Zone: chunk.Zone, RootHash: chunk.RootHash}}}}, now)
	_, _ = session.OnEvent(&gossip.ObjectPullResultEvent{PeerID: "peer-a", Zone: chunk.Zone, Unreachable: true, Err: errors.New("unreachable")}, now)
	if _, err := driver.HandleGossipHostEvent(t.Context(), packet, now); err != nil {
		t.Fatalf("packet error escaped the Driver: %v", err)
	}
	if len(logs) != 1 || logs[0].Event != "packet_failed" || logs[0].Err == nil || logs[0].PeerID != "peer-a" || logs[0].Fields["component"] != "gossip" {
		t.Fatalf("packet warnings = %#v", logs)
	}
	if len(store.updates) != 1 || session.State != gossip.SyncSessionFailed {
		t.Fatalf("checkpoint updates = %#v", store.updates)
	}
}
