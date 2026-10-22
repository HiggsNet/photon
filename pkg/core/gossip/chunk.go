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
	MaxChunkSendTransfers  = 1024
)

var ErrChunkSendCacheFull = errors.New("gossip chunk send cache limits exceeded")

// ChunkSendCacheFullError describes admission pressure, not a malformed packet.
type ChunkSendCacheFullError struct {
	PeerID         string
	Limit          string
	PeerTransfers  int
	Transfers      int
	Bytes          int
	RequestedBytes int
}

func (e *ChunkSendCacheFullError) Error() string {
	return fmt.Sprintf("%s: peer=%s limit=%s peer_transfers=%d/%d transfers=%d/%d bytes=%d/%d requested_bytes=%d", ErrChunkSendCacheFull, e.PeerID, e.Limit, e.PeerTransfers, MaxChunkPeerInflight, e.Transfers, MaxChunkSendTransfers, e.Bytes, MaxChunkSendCacheBytes, e.RequestedBytes)
}

func (e *ChunkSendCacheFullError) Unwrap() error { return ErrChunkSendCacheFull }

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
	active       bool
	lastUsed     time.Time
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

// Put admits one initial send, reusing an identical unexpired transfer. Idle
// repair entries may be evicted under pressure; paced sends are always pinned.
func (c *SentChunkCache) Put(peerID string, transferID []byte, chunks []*ObjectChunk, now time.Time) ([]*ObjectChunk, error) {
	if c == nil || peerID == "" || len(transferID) != 16 || len(chunks) == 0 {
		return nil, errors.New("invalid chunk send cache input")
	}
	requestedBytes := 0
	for i, chunk := range chunks {
		if chunk == nil || int(chunk.Index) != i || int(chunk.Total) != len(chunks) || !bytes.Equal(chunk.TransferID, transferID) {
			return nil, errors.New("invalid chunk send cache parts")
		}
		requestedBytes += len(chunk.Data)
	}
	if requestedBytes == 0 {
		return nil, errors.New("empty chunk send cache payload")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	peerCount := 0
	activePeer, activeCount, activeBytes := 0, 0, 0
	for _, entry := range c.entries {
		if entry.peerID == peerID {
			peerCount++
			if sameChunkObject(entry.chunks, chunks) {
				entry.lastUsed = now
				return cloneObjectChunks(entry.chunks), nil
			}
			if entry.active {
				activePeer++
			}
		}
		if entry.active {
			activeCount++
			activeBytes += entry.bytes
		}
	}
	full := func(limit string) ([]*ObjectChunk, error) {
		return nil, &ChunkSendCacheFullError{PeerID: peerID, Limit: limit, PeerTransfers: peerCount, Transfers: len(c.entries), Bytes: c.bytes, RequestedBytes: requestedBytes}
	}
	if activePeer >= MaxChunkPeerInflight {
		return full("peer_active_transfers")
	}
	if activeCount >= MaxChunkSendTransfers {
		return full("transfers")
	}
	if activeBytes+requestedBytes > MaxChunkSendCacheBytes {
		return full("bytes")
	}
	key := sentTransferKey(peerID, transferID)
	if c.entries[key] != nil {
		return nil, errors.New("chunk transfer id reused for a different object")
	}
	// Admission above proves that reclaiming only idle entries is sufficient.
	// Do not evict any repair data for a request that cannot be admitted.
	for peerCount >= MaxChunkPeerInflight || len(c.entries) >= MaxChunkSendTransfers || c.bytes+requestedBytes > MaxChunkSendCacheBytes {
		oldestKey := ""
		var oldest *sentChunkTransfer
		for candidateKey, candidate := range c.entries {
			if candidate.active || peerCount >= MaxChunkPeerInflight && candidate.peerID != peerID {
				continue
			}
			if oldest == nil || candidate.lastUsed.Before(oldest.lastUsed) || candidate.lastUsed.Equal(oldest.lastUsed) && candidateKey < oldestKey {
				oldestKey, oldest = candidateKey, candidate
			}
		}
		c.removeLocked(oldestKey)
		if oldest.peerID == peerID {
			peerCount--
		}
	}
	entry := &sentChunkTransfer{peerID: peerID, transferID: append([]byte(nil), transferID...), created: now, expires: now.Add(ChunkTransferTTL), active: true, lastUsed: now}
	for _, chunk := range chunks {
		copyChunk := cloneObjectChunk(chunk)
		entry.bytes += len(copyChunk.Data)
		entry.chunks = append(entry.chunks, copyChunk)
	}
	c.entries[key] = entry
	c.bytes += entry.bytes
	return chunks, nil
}

func sameChunkObject(left, right []*ObjectChunk) bool {
	if len(left) != len(right) {
		return false
	}
	a, b := left[0], right[0]
	return a.Object == b.Object && a.Zone == b.Zone && a.Key == b.Key && a.Version == b.Version &&
		bytes.Equal(a.ObjectHash, b.ObjectHash) && bytes.Equal(a.RootHash, b.RootHash) &&
		len(a.Data) == len(b.Data)
}

func cloneObjectChunks(chunks []*ObjectChunk) []*ObjectChunk {
	out := make([]*ObjectChunk, len(chunks))
	for i, chunk := range chunks {
		out[i] = cloneObjectChunk(chunk)
	}
	return out
}

// Activate pins an idle transfer before a resend or repair job starts. Repeated
// requests cannot extend an already active job's lifetime.
func (c *SentChunkCache) Activate(peerID string, transferID []byte, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	entry := c.entries[sentTransferKey(peerID, transferID)]
	if entry == nil {
		return false
	}
	if !entry.active {
		entry.active = true
		entry.expires = now.Add(ChunkTransferTTL)
	}
	entry.lastUsed = now
	return true
}

// Sent releases admission capacity while retaining best-effort NACK repair.
func (c *SentChunkCache) Sent(peerID string, transferID []byte, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry := c.entries[sentTransferKey(peerID, transferID)]; entry != nil {
		entry.active = false
		entry.lastUsed = now
		entry.expires = now.Add(ChunkTransferTTL)
	}
}

func (c *SentChunkCache) Drop(peerID string, transferID []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeLocked(sentTransferKey(peerID, transferID))
}

func (c *SentChunkCache) removeLocked(key string) {
	if entry := c.entries[key]; entry != nil {
		c.bytes -= entry.bytes
	}
	delete(c.entries, key)
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
	entry.lastUsed = now
	result := make([]*ObjectChunk, 0, len(indexes))
	for _, index := range indexes {
		if int(index) >= len(entry.chunks) || entry.chunks[index] == nil {
			continue
		}
		result = append(result, cloneObjectChunk(entry.chunks[index]))
	}
	return result
}

// Chunk reads one detached part for a scheduled send. The existing bounded
// cache remains the only owner of payloads, expiry and transfer limits.
func (c *SentChunkCache) Chunk(peerID string, transferID []byte, index uint16, now time.Time) *ObjectChunk {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	entry := c.entries[sentTransferKey(peerID, transferID)]
	if entry == nil || int(index) >= len(entry.chunks) {
		return nil
	}
	return cloneObjectChunk(entry.chunks[index])
}

func (c *SentChunkCache) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.entries)
	c.bytes = 0
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
			c.removeLocked(key)
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
