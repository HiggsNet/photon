package observability

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestPeerStoreSnapshotIsDetachedAndConcurrent(t *testing.T) {
	store := NewPeerObservabilityStore(8, time.Hour)
	now := time.Unix(100, 0)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				store.Update("peer-a", now, func(snapshot *PeerDiagnostics) {
					snapshot.HintAccepted++
					if snapshot.DatagramStats == nil {
						snapshot.DatagramStats = &PeerDatagramStats{}
					}
					snapshot.DatagramStats.ChunkFallbacks++
				})
			}
		})
	}
	wg.Wait()

	snapshot, ok := store.Snapshot("peer-a", now)
	if !ok || snapshot.HintAccepted != 800 || snapshot.DatagramStats == nil || snapshot.DatagramStats.ChunkFallbacks != 800 {
		t.Fatalf("snapshot = %#v, want 800 fallbacks", snapshot)
	}
	snapshot.DatagramStats.ChunkFallbacks = 0
	again, _ := store.Snapshot("peer-a", now)
	if again.DatagramStats.ChunkFallbacks != 800 {
		t.Fatalf("stored snapshot was mutated through returned pointer: %#v", again)
	}
}

func TestPeerStoreBoundsDeletesAndExpiresEntries(t *testing.T) {
	store := NewPeerObservabilityStore(2, time.Minute)
	base := time.Unix(100, 0)
	update := func(peerID string, now time.Time) {
		store.Update(peerID, now, func(snapshot *PeerDiagnostics) {
			snapshot.ObjectPullStats = &PeerObjectPullStats{LastSourcePeer: peerID}
		})
	}
	update("peer-b", base)
	update("peer-a", base)
	update("peer-c", base.Add(time.Second))

	if _, ok := store.Snapshot("peer-a", base.Add(time.Second)); ok {
		t.Fatal("peer-a was not evicted by deterministic oldest-entry bound")
	}
	if got := store.Len(base.Add(time.Second)); got != 2 {
		t.Fatalf("len = %d, want 2", got)
	}
	store.Delete("peer-b")
	if _, ok := store.Snapshot("peer-b", base.Add(time.Second)); ok {
		t.Fatal("deleted peer-b is still present")
	}
	if got := store.Len(base.Add(2 * time.Minute)); got != 0 {
		t.Fatalf("len after expiry = %d, want 0", got)
	}
}

func TestPeerStoreSnapshotsAreDetached(t *testing.T) {
	store := NewPeerObservabilityStore(4, 0)
	now := time.Unix(100, 0)
	for i := range 2 {
		peerID := fmt.Sprintf("peer-%d", i)
		store.Update(peerID, now, func(snapshot *PeerDiagnostics) {
			snapshot.DatagramStats = &PeerDatagramStats{ChunkRepairChunks: 2}
		})
	}
	all := store.Snapshots(now)
	all["peer-0"].DatagramStats.ChunkRepairChunks = 99
	snapshot, _ := store.Snapshot("peer-0", now)
	if snapshot.DatagramStats.ChunkRepairChunks != 2 {
		t.Fatalf("stored snapshot was mutated through map snapshot: %#v", snapshot)
	}
}
