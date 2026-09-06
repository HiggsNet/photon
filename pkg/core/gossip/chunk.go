package gossip

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	ChunkRepairQuiet       = 150 * time.Millisecond
	ChunkTransferTTL       = 30 * time.Second
	ChunkAssemblyTTL       = 2 * time.Minute
	MaxChunkRepairRounds   = 3
	MaxChunkNACKIndexes    = 128
	MaxChunkPeerInflight   = 4
	MaxChunkObjectBytes    = 8 << 20
	MaxChunkSendCacheBytes = 32 << 20
)

type chunkAssembly struct {
	peerID       string
	object       ObjectPullRequestType
	zone         zone.ZonePath
	key          string
	version      uint64
	rootHash     []byte
	objectHash   []byte
	transferID   []byte
	total        uint16
	chunks       [][]byte
	received     int
	bytes        int
	created      time.Time
	updated      time.Time
	repairRounds int
}

// ChunkAssemblyStore verifies and assembles bounded out-of-order object
// chunks. It is safe for concurrent receive and repair-timer callbacks.
type ChunkAssemblyStore struct {
	mu      sync.Mutex
	entries map[string]*chunkAssembly
}

func NewChunkAssemblyStore() *ChunkAssemblyStore {
	return &ChunkAssemblyStore{entries: make(map[string]*chunkAssembly)}
}

func chunkAssemblyKey(peerID string, chunk *ObjectChunk) string {
	if chunk == nil {
		return ""
	}
	return peerID + "|" + hex.EncodeToString(chunk.TransferID)
}

func (s *ChunkAssemblyStore) Add(peerID string, chunk *ObjectChunk, now time.Time) ([]byte, bool, error) {
	if s == nil || chunk == nil {
		return nil, false, errors.New("chunk assembly input is nil")
	}
	key := chunkAssemblyKey(peerID, chunk)
	if key == "" {
		return nil, false, errors.New("chunk assembly key is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	entry := s.entries[key]
	if entry == nil {
		peerInflight := 0
		for _, candidate := range s.entries {
			if candidate != nil && candidate.peerID == peerID {
				peerInflight++
			}
		}
		if peerInflight >= MaxChunkPeerInflight {
			return nil, false, errors.New("peer chunk inflight limit exceeded")
		}
		entry = &chunkAssembly{
			peerID:     peerID,
			object:     chunk.Object,
			zone:       chunk.Zone,
			key:        chunk.Key,
			version:    chunk.Version,
			rootHash:   append([]byte(nil), chunk.RootHash...),
			objectHash: append([]byte(nil), chunk.ObjectHash...),
			transferID: append([]byte(nil), chunk.TransferID...),
			total:      chunk.Total,
			chunks:     make([][]byte, chunk.Total),
			created:    now,
		}
		s.entries[key] = entry
	}
	if entry.total != chunk.Total || entry.object != chunk.Object || entry.zone != chunk.Zone || entry.key != chunk.Key || entry.version != chunk.Version || !bytes.Equal(entry.transferID, chunk.TransferID) || !bytes.Equal(entry.objectHash, chunk.ObjectHash) || !bytes.Equal(entry.rootHash, chunk.RootHash) {
		delete(s.entries, key)
		return nil, false, errors.New("chunk metadata changed during assembly")
	}
	if chunk.Index >= entry.total {
		return nil, false, errors.New("chunk index out of range")
	}
	if entry.chunks[chunk.Index] == nil {
		entry.chunks[chunk.Index] = append([]byte(nil), chunk.Data...)
		entry.received++
		entry.bytes += len(chunk.Data)
		if entry.bytes > MaxChunkObjectBytes {
			delete(s.entries, key)
			return nil, false, fmt.Errorf("chunk object exceeds max %d bytes", MaxChunkObjectBytes)
		}
	}
	entry.updated = now
	if entry.received != int(entry.total) {
		return nil, false, nil
	}
	data := make([]byte, 0, entry.bytes)
	for _, part := range entry.chunks {
		if part == nil {
			return nil, false, nil
		}
		data = append(data, part...)
	}
	hash := sha256.Sum256(data)
	if !bytes.Equal(hash[:], entry.objectHash) {
		delete(s.entries, key)
		return nil, false, errors.New("chunk object hash mismatch")
	}
	delete(s.entries, key)
	return data, true, nil
}

// RepairDeadline returns the quiet-period deadline for an incomplete transfer.
// Scheduling resources are owned by GossipDriver.
func (s *ChunkAssemblyStore) RepairDeadline(peerID string, chunk *ObjectChunk) (time.Time, bool) {
	if s == nil || chunk == nil {
		return time.Time{}, false
	}
	key := chunkAssemblyKey(peerID, chunk)
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[key]
	if entry == nil || entry.received == int(entry.total) || entry.repairRounds >= MaxChunkRepairRounds {
		return time.Time{}, false
	}
	return entry.updated.Add(ChunkRepairQuiet), true
}

// BuildRepairNACK consumes one repair round at a GossipDriver timer fire.
func (s *ChunkAssemblyStore) BuildRepairNACK(peerID string, transferID []byte) *ObjectChunkNACK {
	if s == nil || peerID == "" || len(transferID) == 0 {
		return nil
	}
	key := peerID + "|" + hex.EncodeToString(transferID)
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[key]
	if entry == nil || entry.received == int(entry.total) || entry.repairRounds >= MaxChunkRepairRounds {
		return nil
	}
	missing := MissingChunkIndexes(entry.chunks, MaxChunkNACKIndexes)
	if len(missing) == 0 {
		return nil
	}
	entry.repairRounds++
	return &ObjectChunkNACK{TransferID: append([]byte(nil), entry.transferID...), Missing: missing}
}

func (s *ChunkAssemblyStore) pruneLocked(now time.Time) {
	for key, entry := range s.entries {
		if entry == nil || now.Sub(entry.updated) > ChunkAssemblyTTL && now.Sub(entry.created) > ChunkAssemblyTTL {
			delete(s.entries, key)
		}
	}
}

func (s *ChunkAssemblyStore) DropPeer(peerID string) {
	if s == nil || peerID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, entry := range s.entries {
		if entry != nil && entry.peerID == peerID {
			delete(s.entries, key)
		}
	}
}

// Close discards every incomplete assembly. It is idempotent and is called by
// the owning GossipDriver.
func (s *ChunkAssemblyStore) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key := range s.entries {
		delete(s.entries, key)
	}
}

type sentChunkTransfer struct {
	peerID       string
	transferID   []byte
	chunks       []*ObjectChunk
	bytes        int
	created      time.Time
	expires      time.Time
	repairRounds int
	lastRequest  string
}

// SentChunkCache retains bounded detached chunks for NACK repair.
type SentChunkCache struct {
	mu      sync.Mutex
	entries map[string]*sentChunkTransfer
	bytes   int
}

func NewSentChunkCache() *SentChunkCache {
	return &SentChunkCache{entries: make(map[string]*sentChunkTransfer)}
}

func sentTransferKey(peerID string, transferID []byte) string {
	return peerID + "|" + hex.EncodeToString(transferID)
}

func (c *SentChunkCache) Put(peerID string, transferID []byte, chunks []*ObjectChunk, now time.Time) bool {
	if c == nil || peerID == "" || len(transferID) != 16 || len(chunks) == 0 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	peerCount := 0
	for _, entry := range c.entries {
		if entry.peerID == peerID {
			peerCount++
		}
	}
	if peerCount >= MaxChunkPeerInflight {
		return false
	}
	entry := &sentChunkTransfer{peerID: peerID, transferID: append([]byte(nil), transferID...), created: now, expires: now.Add(ChunkTransferTTL)}
	for _, chunk := range chunks {
		if chunk == nil {
			continue
		}
		copyChunk := cloneObjectChunk(chunk)
		entry.bytes += len(copyChunk.Data)
		entry.chunks = append(entry.chunks, copyChunk)
	}
	if entry.bytes == 0 || entry.bytes > MaxChunkSendCacheBytes || c.bytes+entry.bytes > MaxChunkSendCacheBytes {
		return false
	}
	key := sentTransferKey(peerID, transferID)
	c.entries[key] = entry
	c.bytes += entry.bytes
	return true
}

func (c *SentChunkCache) Repair(peerID string, nack *ObjectChunkNACK, now time.Time) []*ObjectChunk {
	if c == nil || nack == nil || len(nack.Missing) == 0 || len(nack.Missing) > MaxChunkNACKIndexes {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	entry := c.entries[sentTransferKey(peerID, nack.TransferID)]
	if entry == nil || entry.repairRounds >= MaxChunkRepairRounds {
		return nil
	}
	indexes := append([]uint16(nil), nack.Missing...)
	slices.Sort(indexes)
	parts := make([]string, 0, len(indexes))
	for _, index := range indexes {
		parts = append(parts, string(rune(index)))
	}
	signature := strings.Join(parts, ",")
	if signature == entry.lastRequest {
		return nil
	}
	entry.lastRequest = signature
	entry.repairRounds++
	result := make([]*ObjectChunk, 0, len(indexes))
	for _, index := range indexes {
		if int(index) >= len(entry.chunks) || entry.chunks[index] == nil {
			continue
		}
		result = append(result, cloneObjectChunk(entry.chunks[index]))
	}
	return result
}

func cloneObjectChunk(chunk *ObjectChunk) *ObjectChunk {
	if chunk == nil {
		return nil
	}
	out := *chunk
	out.TransferID = append([]byte(nil), chunk.TransferID...)
	out.RootHash = append([]byte(nil), chunk.RootHash...)
	out.ObjectHash = append([]byte(nil), chunk.ObjectHash...)
	out.Data = append([]byte(nil), chunk.Data...)
	return &out
}

func (c *SentChunkCache) pruneLocked(now time.Time) {
	for key, entry := range c.entries {
		if entry == nil || !entry.expires.After(now) {
			if entry != nil {
				c.bytes -= entry.bytes
			}
			delete(c.entries, key)
		}
	}
}

func MissingChunkIndexes(chunks [][]byte, limit int) []uint16 {
	if limit <= 0 || limit > MaxChunkNACKIndexes {
		limit = MaxChunkNACKIndexes
	}
	missing := make([]uint16, 0)
	for index, chunk := range chunks {
		if chunk == nil {
			missing = append(missing, uint16(index))
			if len(missing) == limit {
				break
			}
		}
	}
	return missing
}
