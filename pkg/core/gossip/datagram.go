package gossip

import (
	"crypto/sha256"
	"errors"
	"fmt"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func MessageWireSize(message *Message) int {
	size, err := WireEncodeSize(message)
	if err != nil {
		return 1 << 30
	}
	return size
}

// MaxObjectChunkDataSize returns the largest ObjectChunk.Data payload whose
// complete worst-case wire message fits budget.
func MaxObjectChunkDataSize(budget int, senderID string, path zone.ZonePath) int {
	if budget <= 0 {
		return 0
	}
	low, high := 1, budget
	best := 0
	for low <= high {
		mid := (low + high) / 2
		data, err := MarshalMessage(&Message{
			Type:      MessageObjectChunk,
			PeerID:    senderID,
			Nonce:     ^uint64(0),
			Timestamp: int64(^uint64(0) >> 1),
			ObjectChunk: &ObjectChunk{
				TransferID: make([]byte, 16),
				Object:     ObjectPullZone,
				Zone:       path,
				RootHash:   make([]byte, sha256.Size),
				ObjectHash: make([]byte, sha256.Size),
				Index:      ^uint16(0) - 1,
				Total:      ^uint16(0),
				Data:       make([]byte, mid),
			},
		})
		if err == nil && len(data) <= budget {
			best = mid
			low = mid + 1
			continue
		}
		high = mid - 1
	}
	return best
}

// BuildZoneSnapshotChunks encodes a detached snapshot into bounded object
// chunks. The caller supplies the random transfer ID and owns the returned
// chunks; caching and sending remain executor responsibilities.
func BuildZoneSnapshotChunks(snapshot *corestate.ZoneSnapshot, budget int, senderID string, transferID []byte) ([]*ObjectChunk, error) {
	if snapshot == nil {
		return nil, errors.New("zone snapshot is nil")
	}
	if len(transferID) != 16 {
		return nil, errors.New("chunk transfer id must be 16 bytes")
	}
	data, err := EncodeZoneSnapshotObject(snapshot)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxChunkObjectBytes {
		return nil, fmt.Errorf("chunk zone snapshot %s exceeds max %d bytes", snapshot.Zone, MaxChunkObjectBytes)
	}
	chunkSize := MaxObjectChunkDataSize(budget, senderID, snapshot.Zone)
	if chunkSize <= 0 {
		return nil, ErrMessageTooLarge
	}
	total := (len(data) + chunkSize - 1) / chunkSize
	if total <= 0 || total > int(^uint16(0)) {
		return nil, fmt.Errorf("chunk zone snapshot %s needs invalid chunk count %d", snapshot.Zone, total)
	}
	objectHash := sha256.Sum256(data)
	rootHash := corestate.ZoneRoot(corestate.ZoneStateFromSnapshot(snapshot))
	chunks := make([]*ObjectChunk, 0, total)
	for i := range total {
		start := i * chunkSize
		end := min(start+chunkSize, len(data))
		chunks = append(chunks, &ObjectChunk{
			TransferID: append([]byte(nil), transferID...),
			Object:     ObjectPullZone,
			Zone:       snapshot.Zone,
			RootHash:   append([]byte(nil), rootHash...),
			ObjectHash: append([]byte(nil), objectHash[:]...),
			Index:      uint16(i),
			Total:      uint16(total),
			Data:       data[start:end],
		})
	}
	return chunks, nil
}
