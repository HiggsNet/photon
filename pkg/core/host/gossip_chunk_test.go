package host

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestGossipDriverHandleGossipObjectChunkCompletesIntoCommonEventQueue(t *testing.T) {
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
	for index, chunk := range chunks {
		result, err := driver.HandleGossipObjectChunk(context.Background(), &gossip.Message{PeerID: "peer-a", ObjectChunk: chunk}, now)
		if err != nil {
			t.Fatal(err)
		}
		if index < len(chunks)-1 && result.Complete {
			t.Fatalf("chunk %d completed early", index)
		}
		if index == len(chunks)-1 && (!result.Complete || !result.ChunkFallback) {
			t.Fatalf("final result = %#v", result)
		}
	}
	event, ok := driver.GossipSessionEventFor(<-driver.Events())
	completed, completedOK := event.(*gossip.ObjectChunkEvent)
	if !ok || !completedOK || completed.Snapshot == nil || completed.Snapshot.Zone != snapshot.Zone {
		t.Fatalf("completion event = %#v", event)
	}
}

func TestGossipDriverHandleGossipObjectChunkRejectsAndCheckpointsInvalidObject(t *testing.T) {
	now := time.Unix(100, 0)
	store := &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}}
	driver := NewGossipDriver(nil, 2, store, GossipDriverConfig{})
	defer driver.Stop()
	data := []byte("invalid snapshot")
	hash := sha256.Sum256([]byte("different"))
	chunk := &gossip.ObjectChunk{
		TransferID: []byte("0123456789abcdef"), Object: gossip.ObjectPullZone,
		Zone: "remote.catofes.", RootHash: []byte("advertised-root"), ObjectHash: hash[:], Index: 0, Total: 1, Data: data,
	}
	result, err := driver.HandleGossipObjectChunk(context.Background(), &gossip.Message{PeerID: "peer-a", ObjectChunk: chunk}, now)
	if err == nil || result.CheckpointErr != nil {
		t.Fatalf("result/error = %#v/%v", result, err)
	}
	if len(store.updates) != 1 || store.updates[0]["peer-a"].Reject == nil {
		t.Fatalf("checkpoint updates = %#v", store.updates)
	}
	event, ok := driver.GossipSessionEventFor(<-driver.Events())
	rejected, rejectedOK := event.(*gossip.ObjectChunkEvent)
	if !ok || !rejectedOK || !errors.Is(rejected.Err, err) {
		t.Fatalf("rejection event = %#v", event)
	}
}
