package gossip

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"
)

func testSentChunks(transferID []byte) []*ObjectChunk {
	chunks := make([]*ObjectChunk, 3)
	for i := range chunks {
		chunks[i] = &ObjectChunk{TransferID: transferID, Object: ObjectPullZone, Zone: "catofes.", ObjectHash: make([]byte, 32), Index: uint16(i), Total: 3, Data: []byte{byte(i)}}
	}
	return chunks
}

func TestSentChunkCacheRepairsMissingWithoutDuplicateAmplification(t *testing.T) {
	now := time.Unix(100, 0)
	id := []byte("0123456789abcdef")
	cache := NewSentChunkCache()
	if _, err := cache.Put("peer-a", id, testSentChunks(id), now); err != nil {
		t.Fatal(err)
	}
	nack := &ObjectChunkNACK{TransferID: id, Missing: []uint16{2, 0}}
	got := cache.Repair("peer-a", nack, now)
	if len(got) != 2 || got[0].Index != 0 || got[1].Index != 2 {
		t.Fatalf("repair = %#v", got)
	}
	if duplicate := cache.Repair("peer-a", nack, now); len(duplicate) != 0 {
		t.Fatalf("duplicate repair sent %d chunks", len(duplicate))
	}
}

func TestSentChunkCacheRejectsWrongOrExpiredTransfer(t *testing.T) {
	now := time.Unix(100, 0)
	id := []byte("0123456789abcdef")
	cache := NewSentChunkCache()
	if _, err := cache.Put("peer-a", id, testSentChunks(id), now); err != nil {
		t.Fatal(err)
	}
	if got := cache.Repair("peer-a", &ObjectChunkNACK{TransferID: []byte("fedcba9876543210"), Missing: []uint16{0}}, now); len(got) != 0 {
		t.Fatal("wrong transfer id repaired")
	}
	if got := cache.Repair("peer-a", &ObjectChunkNACK{TransferID: id, Missing: []uint16{0}}, now.Add(ChunkTransferTTL)); len(got) != 0 {
		t.Fatal("expired transfer repaired")
	}
}

func TestMissingChunkIndexesIsBounded(t *testing.T) {
	chunks := make([][]byte, MaxChunkNACKIndexes+10)
	chunks[1] = []byte("present")
	got := MissingChunkIndexes(chunks, MaxChunkNACKIndexes)
	if len(got) != MaxChunkNACKIndexes {
		t.Fatalf("missing = %d", len(got))
	}
	if got[0] != 0 || got[1] != 2 {
		t.Fatalf("missing starts with %v", got[:2])
	}
}

func TestChunkAssemblyQuietNACKRepairsOutOfOrderLoss(t *testing.T) {
	id := []byte("0123456789abcdef")
	data := []byte("zero-one-two")
	hash := sha256.Sum256(data)
	chunks := []*ObjectChunk{
		{TransferID: id, Object: ObjectPullZone, Zone: "catofes.", ObjectHash: hash[:], Index: 0, Total: 3, Data: []byte("zero-")},
		{TransferID: id, Object: ObjectPullZone, Zone: "catofes.", ObjectHash: hash[:], Index: 1, Total: 3, Data: []byte("one-")},
		{TransferID: id, Object: ObjectPullZone, Zone: "catofes.", ObjectHash: hash[:], Index: 2, Total: 3, Data: []byte("two")},
	}
	store := NewChunkAssemblyStore()
	now := time.Unix(100, 0)
	for _, index := range []int{2, 0} {
		if _, complete, err := store.Add("peer-a", chunks[index], now); err != nil || complete {
			t.Fatalf("add[%d]: complete=%t err=%v", index, complete, err)
		}
	}
	if deadline, ok := store.RepairDeadline("peer-a", chunks[0]); !ok || !deadline.Equal(now.Add(ChunkRepairQuiet)) {
		t.Fatalf("repair deadline = %v, %t", deadline, ok)
	}
	nack := store.BuildRepairNACK("peer-a", id)
	if nack == nil || len(nack.Missing) != 1 || nack.Missing[0] != 1 {
		t.Fatalf("nack = %#v", nack)
	}
	got, complete, err := store.Add("peer-a", chunks[1], now)
	if err != nil || !complete || string(got) != string(data) {
		t.Fatalf("repair completion: data=%q complete=%t err=%v", got, complete, err)
	}
}

func TestChunkAssemblyDropPeerEnforcesRoundDeadline(t *testing.T) {
	id := []byte("0123456789abcdef")
	chunk := &ObjectChunk{TransferID: id, Object: ObjectPullZone, Zone: "catofes.", ObjectHash: make([]byte, 32), Index: 0, Total: 2, Data: []byte("partial")}
	store := NewChunkAssemblyStore()
	if _, _, err := store.Add("peer-a", chunk, time.Now()); err != nil {
		t.Fatal(err)
	}
	store.DropPeer("peer-a")
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.entries) != 0 {
		t.Fatalf("assemblies after deadline = %d", len(store.entries))
	}
}

func TestChunkAssemblyCloseDiscardsPendingRepair(t *testing.T) {
	id := []byte("0123456789abcdef")
	chunk := &ObjectChunk{TransferID: id, Object: ObjectPullZone, Zone: "catofes.", ObjectHash: make([]byte, 32), Index: 0, Total: 2, Data: []byte("partial")}
	store := NewChunkAssemblyStore()
	if _, _, err := store.Add("peer-a", chunk, time.Now()); err != nil {
		t.Fatal(err)
	}
	store.Close()
	store.Close()
	if nack := store.BuildRepairNACK("peer-a", id); nack != nil {
		t.Fatalf("repair remains after close: %#v", nack)
	}
}

func TestChunkAssemblyRejectsMetadataChange(t *testing.T) {
	now := time.Unix(100, 0)
	id := []byte("0123456789abcdef")
	first := &ObjectChunk{TransferID: id, Object: ObjectPullZone, Zone: "catofes.", ObjectHash: make([]byte, 32), Index: 0, Total: 2, Data: []byte("a")}
	store := NewChunkAssemblyStore()
	if _, _, err := store.Add("peer-a", first, now); err != nil {
		t.Fatal(err)
	}
	changed := *first
	changed.Total = 3
	if _, _, err := store.Add("peer-a", &changed, now); err == nil || !strings.Contains(err.Error(), "metadata changed") {
		t.Fatalf("error = %v, want metadata change failure", err)
	}
}

func TestChunkAssemblyRejectsObjectHashMismatch(t *testing.T) {
	chunk := &ObjectChunk{
		TransferID: []byte("0123456789abcdef"),
		Object:     ObjectPullZone,
		Zone:       "catofes.",
		ObjectHash: make([]byte, sha256.Size),
		Index:      0,
		Total:      1,
		Data:       []byte("tampered"),
	}
	if _, _, err := NewChunkAssemblyStore().Add("peer-a", chunk, time.Unix(100, 0)); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("error = %v, want hash mismatch", err)
	}
}

func TestChunkAssemblyBoundsPerPeerInflight(t *testing.T) {
	store := NewChunkAssemblyStore()
	now := time.Unix(100, 0)
	for i := range MaxChunkPeerInflight + 1 {
		id := []byte("0123456789abcde0")
		id[len(id)-1] += byte(i)
		chunk := &ObjectChunk{TransferID: id, Object: ObjectPullZone, Zone: "catofes.", ObjectHash: make([]byte, sha256.Size), Index: 0, Total: 2, Data: []byte("partial")}
		_, _, err := store.Add("peer-a", chunk, now)
		if i < MaxChunkPeerInflight && err != nil {
			t.Fatalf("Add[%d]: %v", i, err)
		}
		if i == MaxChunkPeerInflight && (err == nil || !strings.Contains(err.Error(), "inflight limit")) {
			t.Fatalf("Add[%d] error = %v, want inflight limit", i, err)
		}
	}
}

func TestSentChunkCacheDetachesInputAndOutput(t *testing.T) {
	now := time.Unix(100, 0)
	id := []byte("0123456789abcdef")
	chunks := testSentChunks(id)
	want := append([]byte(nil), chunks[0].Data...)
	cache := NewSentChunkCache()
	if _, err := cache.Put("peer-a", id, chunks, now); err != nil {
		t.Fatal(err)
	}
	chunks[0].Data[0] ^= 0xff
	first := cache.Repair("peer-a", &ObjectChunkNACK{TransferID: id, Missing: []uint16{0}}, now)
	if len(first) != 1 || string(first[0].Data) != string(want) {
		t.Fatalf("first repair = %#v, want detached data %v", first, want)
	}
	first[0].Data[0] ^= 0xff
	first[0].TransferID[0] ^= 0xff
	first[0].ObjectHash[0] ^= 0xff
	second := cache.Repair("peer-a", &ObjectChunkNACK{TransferID: id, Missing: []uint16{0, 1}}, now)
	if len(second) != 2 || string(second[0].Data) != string(want) || string(second[0].TransferID) != string(id) || second[0].ObjectHash[0] != 0 {
		t.Fatalf("second repair = %#v, cache mutated through output", second)
	}
}
