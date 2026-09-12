package observability

import (
	"sync"
	"time"
)

// PeerDiagnostics contains common gossip observations that are safe to lose
// on daemon restart. Values returned by PeerObservabilityStore are detached.
type PeerDiagnostics struct {
	LastUpdateSource      string
	LastRelaySuppression  string
	LastRelaySuppressedAt int64
	ObservedSource        string
	ActivePullState       string
	ActivePullLastEvent   string
	ActivePullUpdatedUnix int64
	HintAccepted          int64
	HintSuppressed        int64
	LastHintUnix          int64
	LastHintReason        string
	LastHintSuppression   string
	ReadOnlyResponder     int64
	LastResponderUnix     int64
	LastResponderKind     string
	LastResponderZone     string
	DatagramStats         *PeerDatagramStats
	ObjectPullStats       *PeerObjectPullStats
}

type PeerDatagramStats struct {
	TooLargeDropped           int64  `json:"too_large_dropped,omitempty"`
	DigestOnlyAnnounces       int64  `json:"digest_only_announces,omitempty"`
	ChunkFallbacks            int64  `json:"chunk_fallbacks,omitempty"`
	ChunkRepairNACKs          int64  `json:"chunk_repair_nacks,omitempty"`
	ChunkRepairChunks         int64  `json:"chunk_repair_chunks,omitempty"`
	ChunkRepairIgnored        int64  `json:"chunk_repair_ignored,omitempty"`
	LastCatalogUnix           int64  `json:"last_catalog_unix,omitempty"`
	LastCatalogRootHex        string `json:"last_catalog_root_hex,omitempty"`
	LastCatalogZoneCount      int    `json:"last_catalog_zone_count,omitempty"`
	LastCatalogCursor         string `json:"last_catalog_cursor,omitempty"`
	LastCatalogPageEntries    int    `json:"last_catalog_page_entries,omitempty"`
	LastCatalogRejectedReason string `json:"last_catalog_rejected_reason,omitempty"`
	LastTooLargeUnix          int64  `json:"last_too_large_unix,omitempty"`
	LastTooLargeDirection     string `json:"last_too_large_direction,omitempty"`
	LastTooLargeObject        string `json:"last_too_large_object,omitempty"`
	LastTooLargeZone          string `json:"last_too_large_zone,omitempty"`
	LastTooLargeKey           string `json:"last_too_large_key,omitempty"`
	LastTooLargeBytes         int    `json:"last_too_large_bytes,omitempty"`
	LastTooLargeLimit         int    `json:"last_too_large_limit,omitempty"`
}

type PeerObjectPullStats struct {
	Attempts               int64  `json:"attempts,omitempty"`
	Successes              int64  `json:"successes,omitempty"`
	Failures               int64  `json:"failures,omitempty"`
	LargeObjectUnreachable int64  `json:"large_object_unreachable,omitempty"`
	LastUnix               int64  `json:"last_unix,omitempty"`
	LastFailure            error  `json:"-"`
	LastObject             string `json:"last_object,omitempty"`
	LastZone               string `json:"last_zone,omitempty"`
	LastKey                string `json:"last_key,omitempty"`
	LastBytes              int    `json:"last_bytes,omitempty"`
	LastSourcePeer         string `json:"last_source_peer,omitempty"`
	LastUnreachable        bool   `json:"last_unreachable,omitempty"`
}

type peerEntry struct {
	diagnostics PeerDiagnostics
	updatedAt   time.Time
}

// PeerObservabilityStore owns bounded, non-persistent per-peer diagnostics.
type PeerObservabilityStore struct {
	mu         sync.RWMutex
	entries    map[string]peerEntry
	maxEntries int
	ttl        time.Duration
}

func NewPeerObservabilityStore(maxEntries int, ttl time.Duration) *PeerObservabilityStore {
	if maxEntries < 1 {
		maxEntries = 1
	}
	return &PeerObservabilityStore{entries: make(map[string]peerEntry), maxEntries: maxEntries, ttl: ttl}
}

func (s *PeerObservabilityStore) Update(peerID string, now time.Time, fn func(*PeerDiagnostics)) {
	if s == nil || peerID == "" || fn == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked(now)
	entry, exists := s.entries[peerID]
	if !exists && len(s.entries) >= s.maxEntries {
		s.evictOldestLocked()
	}
	fn(&entry.diagnostics)
	entry.updatedAt = now
	s.entries[peerID] = entry
}

func (s *PeerObservabilityStore) Snapshot(peerID string, now time.Time) (PeerDiagnostics, bool) {
	if s == nil || peerID == "" {
		return PeerDiagnostics{}, false
	}
	s.mu.RLock()
	entry, ok := s.entries[peerID]
	expired := ok && s.expired(entry, now)
	if ok && !expired {
		out := clonePeerDiagnostics(entry.diagnostics)
		s.mu.RUnlock()
		return out, true
	}
	s.mu.RUnlock()
	if expired {
		s.mu.Lock()
		if current, exists := s.entries[peerID]; exists && s.expired(current, now) {
			delete(s.entries, peerID)
		}
		s.mu.Unlock()
	}
	return PeerDiagnostics{}, false
}

func (s *PeerObservabilityStore) Snapshots(now time.Time) map[string]PeerDiagnostics {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked(now)
	out := make(map[string]PeerDiagnostics, len(s.entries))
	for peerID, entry := range s.entries {
		out[peerID] = clonePeerDiagnostics(entry.diagnostics)
	}
	return out
}

func (s *PeerObservabilityStore) Delete(peerID string) {
	if s == nil || peerID == "" {
		return
	}
	s.mu.Lock()
	delete(s.entries, peerID)
	s.mu.Unlock()
}

func (s *PeerObservabilityStore) PurgeExpired(now time.Time) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.purgeExpiredLocked(now)
}

func (s *PeerObservabilityStore) Len(now time.Time) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked(now)
	return len(s.entries)
}

func (s *PeerObservabilityStore) expired(entry peerEntry, now time.Time) bool {
	return s.ttl > 0 && !now.IsZero() && !entry.updatedAt.IsZero() && !now.Before(entry.updatedAt.Add(s.ttl))
}

func (s *PeerObservabilityStore) purgeExpiredLocked(now time.Time) int {
	if s.ttl <= 0 || now.IsZero() {
		return 0
	}
	purged := 0
	for peerID, entry := range s.entries {
		if s.expired(entry, now) {
			delete(s.entries, peerID)
			purged++
		}
	}
	return purged
}

func (s *PeerObservabilityStore) evictOldestLocked() {
	var oldestID string
	var oldest time.Time
	for peerID, entry := range s.entries {
		if oldestID == "" || entry.updatedAt.Before(oldest) || entry.updatedAt.Equal(oldest) && peerID < oldestID {
			oldestID = peerID
			oldest = entry.updatedAt
		}
	}
	if oldestID != "" {
		delete(s.entries, oldestID)
	}
}

func clonePeerDiagnostics(in PeerDiagnostics) PeerDiagnostics {
	out := in
	if in.DatagramStats != nil {
		stats := *in.DatagramStats
		out.DatagramStats = &stats
	}
	if in.ObjectPullStats != nil {
		stats := *in.ObjectPullStats
		out.ObjectPullStats = &stats
	}
	return out
}
