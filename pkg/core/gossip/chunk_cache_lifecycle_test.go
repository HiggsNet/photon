package gossip

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func cacheLifecycleParts(n int, payload []byte) ([]byte, []*ObjectChunk) {
	id := []byte(fmt.Sprintf("%016d", n))
	hash := sha256.Sum256(payload)
	return id, []*ObjectChunk{{TransferID: id, Object: ObjectPullZone, Zone: zone.ZonePath(fmt.Sprintf("zone%d.", n)), ObjectHash: hash[:], Total: 1, Data: payload}}
}

func TestSentChunkCacheReusesObjectWithoutOccupyingAnotherSlot(t *testing.T) {
	cache := NewSentChunkCache()
	now := time.Unix(100, 0)
	id, chunks := cacheLifecycleParts(1, []byte("snapshot"))
	if _, err := cache.Put("peer", id, chunks, now); err != nil {
		t.Fatal(err)
	}
	otherID := []byte("different-id-123")
	for _, chunk := range chunks {
		chunk.TransferID = otherID
	}
	reused, err := cache.Put("peer", otherID, chunks, now)
	if err != nil || string(reused[0].TransferID) != string(id) || len(cache.entries) != 1 || cache.bytes != len("snapshot") {
		t.Fatalf("reuse=%v err=%v entries=%d bytes=%d", reused, err, len(cache.entries), cache.bytes)
	}
	reused[0].Data[0] = 'X'
	if got := cache.Chunk("peer", id, 0, now); string(got.Data) != "snapshot" {
		t.Fatal("reused payload aliases cache")
	}
}

func TestSentChunkCacheReclaimsIdleEntriesAndPinsActiveSends(t *testing.T) {
	cache := NewSentChunkCache()
	now := time.Unix(100, 0)
	for n := range MaxChunkPeerInflight {
		id, chunks := cacheLifecycleParts(n, []byte{byte(n)})
		if _, err := cache.Put("peer", id, chunks, now); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			cache.Sent("peer", id, now.Add(time.Duration(n)*time.Millisecond))
		}
	}
	id, chunks := cacheLifecycleParts(4, []byte("new"))
	if _, err := cache.Put("peer", id, chunks, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	pinned, _ := cacheLifecycleParts(0, nil)
	evicted, _ := cacheLifecycleParts(1, nil)
	recent, _ := cacheLifecycleParts(3, nil)
	if cache.Chunk("peer", pinned, 0, now) == nil || cache.Chunk("peer", evicted, 0, now) != nil || cache.Chunk("peer", recent, 0, now) == nil {
		t.Fatal("eviction did not preserve the active send and recent repair data")
	}
	if len(cache.entries) != MaxChunkPeerInflight || cache.bytes != 6 {
		t.Fatalf("entries/bytes=%d/%d", len(cache.entries), cache.bytes)
	}
	if got := cache.Repair("peer", &ObjectChunkNACK{TransferID: recent, Missing: []uint16{0}}, now); len(got) != 1 {
		t.Fatal("retained idle transfer cannot be repaired")
	}
}

func TestSentChunkCacheActiveLimitDoesNotEvictOtherPeersRepairData(t *testing.T) {
	cache := NewSentChunkCache()
	now := time.Unix(100, 0)
	for n := range MaxChunkPeerInflight {
		id, chunks := cacheLifecycleParts(n, []byte("data"))
		if _, err := cache.Put("peer", id, chunks, now); err != nil {
			t.Fatal(err)
		}
	}
	otherID, other := cacheLifecycleParts(10, []byte("repair"))
	if _, err := cache.Put("other", otherID, other, now); err != nil {
		t.Fatal(err)
	}
	cache.Sent("other", otherID, now)
	id, chunks := cacheLifecycleParts(4, []byte("new"))
	_, err := cache.Put("peer", id, chunks, now)
	var capacity *ChunkSendCacheFullError
	if !errors.As(err, &capacity) || capacity.Limit != "peer_active_transfers" || capacity.PeerTransfers != 4 || RejectReason(err) != "resource_limited" {
		t.Fatalf("capacity error=%v", err)
	}
	if cache.Chunk("other", otherID, 0, now) == nil {
		t.Fatal("failed admission discarded another peer's repair data")
	}
	oldID, _ := cacheLifecycleParts(0, nil)
	cache.Drop("peer", oldID)
	if _, err := cache.Put("peer", id, chunks, now); err != nil {
		t.Fatal(err)
	}
	if cache.bytes != 21 {
		t.Fatalf("drop/admit byte accounting=%d", cache.bytes)
	}
}

func TestSentChunkCacheGlobalByteLimitAndIdleReclamation(t *testing.T) {
	cache := NewSentChunkCache()
	now := time.Unix(100, 0)
	payload := make([]byte, MaxChunkObjectBytes)
	for n := range 4 {
		id, chunks := cacheLifecycleParts(n, payload)
		if _, err := cache.Put(fmt.Sprint(n), id, chunks, now); err != nil {
			t.Fatal(err)
		}
	}
	id, chunks := cacheLifecycleParts(4, []byte{1})
	_, err := cache.Put("4", id, chunks, now)
	var capacity *ChunkSendCacheFullError
	if !errors.As(err, &capacity) || capacity.Limit != "bytes" || capacity.Bytes != MaxChunkSendCacheBytes || len(cache.entries) != 4 {
		t.Fatalf("capacity=%v entries=%d", err, len(cache.entries))
	}
	idle, _ := cacheLifecycleParts(0, nil)
	cache.Sent("0", idle, now)
	if _, err := cache.Put("4", id, chunks, now); err != nil {
		t.Fatal(err)
	}
	if cache.bytes != 3*MaxChunkObjectBytes+1 || cache.Chunk("0", idle, 0, now) != nil {
		t.Fatalf("idle payload not reclaimed: bytes=%d", cache.bytes)
	}
}

func TestSentChunkCacheGlobalEntryLimitAndExpiry(t *testing.T) {
	cache := NewSentChunkCache()
	now := time.Unix(100, 0)
	for n := range MaxChunkSendTransfers {
		id, chunks := cacheLifecycleParts(n, []byte{1})
		if _, err := cache.Put(fmt.Sprint(n), id, chunks, now); err != nil {
			t.Fatal(err)
		}
	}
	id, chunks := cacheLifecycleParts(MaxChunkSendTransfers, []byte{1})
	_, err := cache.Put("new", id, chunks, now)
	var capacity *ChunkSendCacheFullError
	if !errors.As(err, &capacity) || capacity.Limit != "transfers" {
		t.Fatalf("entry capacity=%v", err)
	}
	if _, err := cache.Put("new", id, chunks, now.Add(ChunkTransferTTL)); err != nil {
		t.Fatal(err)
	}
	if len(cache.entries) != 1 || cache.bytes != 1 {
		t.Fatalf("expired entries retained: %d bytes=%d", len(cache.entries), cache.bytes)
	}
}
