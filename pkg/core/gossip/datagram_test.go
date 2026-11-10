package gossip

import (
	"bytes"
	"testing"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestBuildZoneSnapshotChunksFitsWireBudgetAndRoundTrips(t *testing.T) {
	snapshot := &corestate.ZoneSnapshot{
		Zone:      "node-a.catofes.",
		Authority: &zone.ZoneAuthority{Zone: "node-a.catofes.", Epoch: 1, Threshold: 1},
		Records: map[string]*zone.Record{
			"large": {Zone: "node-a.catofes.", Key: "large", Value: bytes.Repeat([]byte("x"), 3000)},
		},
	}
	id := []byte("0123456789abcdef")
	chunks, err := BuildZoneSnapshotChunks(snapshot, DefaultDatagramBudget, "sender.catofes.", id)
	if err != nil {
		t.Fatalf("BuildZoneSnapshotChunks: %v", err)
	}
	if len(chunks) < 2 {
		t.Fatalf("chunks = %d, want chunked object", len(chunks))
	}
	var encoded []byte
	for i, chunk := range chunks {
		if chunk.Index != uint16(i) || int(chunk.Total) != len(chunks) || !bytes.Equal(chunk.TransferID, id) {
			t.Fatalf("chunk[%d] metadata = %#v", i, chunk)
		}
		message := &Message{Type: MessageObjectChunk, PeerID: "sender.catofes.", Nonce: ^uint64(0), Timestamp: int64(^uint64(0) >> 1), ObjectChunk: chunk}
		if size, err := WireEncodeSizeForPeer(message, "test-peer"); err != nil || size > DefaultDatagramBudget {
			t.Fatalf("chunk[%d] wire size = %d, want <= %d", i, size, DefaultDatagramBudget)
		}
		encoded = append(encoded, chunk.Data...)
	}
	decoded, err := DecodeZoneSnapshotObject(encoded)
	if err != nil {
		t.Fatalf("DecodeZoneSnapshotObject: %v", err)
	}
	if decoded.Zone != snapshot.Zone || len(decoded.Records["large"].Value) != 3000 {
		t.Fatalf("decoded snapshot = %#v", decoded)
	}
}

func TestBuildZoneSnapshotChunksRejectsTransferIDAndTinyBudget(t *testing.T) {
	snapshot := &corestate.ZoneSnapshot{Zone: "node-a.catofes.", Authority: &zone.ZoneAuthority{Zone: "node-a.catofes."}}
	if _, err := BuildZoneSnapshotChunks(snapshot, DefaultDatagramBudget, "sender", []byte("short")); err == nil {
		t.Fatal("short transfer ID accepted")
	}
	if _, err := BuildZoneSnapshotChunks(snapshot, 1, "sender", []byte("0123456789abcdef")); err == nil {
		t.Fatal("tiny datagram budget accepted")
	}
}
