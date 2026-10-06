package state

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

// PatchField distinguishes an omitted field from an explicit zero value.
type PatchField[T any] struct {
	Set   bool
	Value T
}

// PeerCheckpointPatch is a replayable, typed restart-hint mutation. It
// cannot modify verified Network state or install live session resources.
type PeerCheckpointPatch struct {
	LastSyncUnix       PatchField[int64]
	LastAttemptUnix    PatchField[int64]
	BackoffUntilUnix   PatchField[int64]
	FailureCount       PatchField[int]
	LastRelayUnix      PatchField[int64]
	LastRelayRootHex   PatchField[string]
	DiscoveredEndpoint PatchField[string]
	DiscoveredAtUnix   PatchField[int64]
	ObservedEndpoint   PatchField[string]
	ObservedFirstUnix  PatchField[int64]
	ObservedLastUnix   PatchField[int64]
	ObservedSyncUnix   PatchField[int64]
	ObservedUntilUnix  PatchField[int64]
	ObservedFailures   PatchField[int]
	ObservedGrace      PatchField[[]ObservedGraceEndpoint]
	LastFailure        PatchField[*PeerFailure]
	Reject             map[zone.ZonePath]RejectedObject
	ClearRejected      []zone.ZonePath
}

// CheckpointCommitFunc persists only affected peers before publishing them in memory.
// A nil peer deletes its checkpoint. Values are detached; no verified data is supplied.
type CheckpointCommitFunc func(context.Context, map[string]*PeerCheckpoint, VerifiedRevision) error

func (store *Store) UpdatePeerCheckpoint(ctx context.Context, peerID string, patch PeerCheckpointPatch) (CommitResult, error) {
	return store.UpdatePeerCheckpoints(ctx, map[string]PeerCheckpointPatch{peerID: patch})
}

// UpdatePeerCheckpoints applies only specified fields, copying only affected peers.
func (store *Store) UpdatePeerCheckpoints(ctx context.Context, patches map[string]PeerCheckpointPatch) (CommitResult, error) {
	return store.changePeerCheckpoints(ctx, patches, nil)
}

func (store *Store) DeletePeerCheckpoints(ctx context.Context, peerIDs []string) (CommitResult, error) {
	return store.changePeerCheckpoints(ctx, nil, peerIDs)
}

func (store *Store) changePeerCheckpoints(ctx context.Context, patches map[string]PeerCheckpointPatch, deleted []string) (CommitResult, error) {
	if store == nil {
		return CommitResult{}, ErrVerifiedStoreClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	store.writeMu.Lock()
	defer store.writeMu.Unlock()
	store.mu.RLock()
	if store.closed {
		store.mu.RUnlock()
		return CommitResult{}, ErrVerifiedStoreClosed
	}
	revision := store.revision
	// writeMu excludes all writers until publication. Public reads are detached.
	peers := store.gossip.Peers
	store.mu.RUnlock()
	updates := make(map[string]*PeerCheckpoint)
	for peerID, patch := range patches {
		if peerID == "" {
			return CommitResult{}, errors.New("peer id is empty")
		}
		before, existed := peers[peerID]
		after := clonePeerCheckpoint(before)
		applyPeerCheckpointPatch(&after, patch)
		if (!existed && peerCheckpointEmpty(after)) || (existed && reflect.DeepEqual(before, after)) {
			continue
		}
		updates[peerID] = &after
	}
	for _, peerID := range deleted {
		if peerID == "" {
			return CommitResult{}, errors.New("peer id is empty")
		}
		if _, exists := peers[peerID]; exists {
			updates[peerID] = nil
		}
	}
	changes := ChangeSet{VerifiedRevision: revision}
	if len(updates) == 0 {
		return CommitResult{Changes: changes}, nil
	}
	if err := ctx.Err(); err != nil {
		return CommitResult{}, err
	}
	if store.commitCheckpoints != nil {
		detached := make(map[string]*PeerCheckpoint, len(updates))
		for id, peer := range updates {
			if peer == nil {
				detached[id] = nil
			} else {
				value := clonePeerCheckpoint(*peer)
				detached[id] = &value
			}
		}
		if err := store.commitCheckpoints(ctx, detached, revision); err != nil {
			return CommitResult{}, err
		}
	} else if store.commit != nil {
		return CommitResult{}, errors.New("checkpoint persistence callback is missing")
	}
	store.mu.Lock()
	for id, peer := range updates {
		if peer == nil {
			delete(store.gossip.Peers, id)
		} else {
			store.gossip.Peers[id] = *peer
		}
	}
	store.mu.Unlock()
	changes.GossipCheckpointChanged = true
	return CommitResult{Committed: true, Changes: changes}, nil
}

func applyPeerCheckpointPatch(metadata *PeerCheckpoint, patch PeerCheckpointPatch) {
	if metadata == nil {
		return
	}
	applyPatchField(&metadata.LastSyncUnix, patch.LastSyncUnix)
	applyPatchField(&metadata.LastAttemptUnix, patch.LastAttemptUnix)
	applyPatchField(&metadata.BackoffUntilUnix, patch.BackoffUntilUnix)
	applyPatchField(&metadata.FailureCount, patch.FailureCount)
	applyPatchField(&metadata.LastRelayUnix, patch.LastRelayUnix)
	applyPatchField(&metadata.LastRelayCatalogRootHex, patch.LastRelayRootHex)
	applyPatchField(&metadata.DiscoveredEndpoint, patch.DiscoveredEndpoint)
	applyPatchField(&metadata.DiscoveredAtUnix, patch.DiscoveredAtUnix)
	applyPatchField(&metadata.ObservedEndpoint, patch.ObservedEndpoint)
	applyPatchField(&metadata.ObservedFirstSeenUnix, patch.ObservedFirstUnix)
	applyPatchField(&metadata.ObservedLastSeenUnix, patch.ObservedLastUnix)
	applyPatchField(&metadata.ObservedLastSyncUnix, patch.ObservedSyncUnix)
	applyPatchField(&metadata.ObservedUntilUnix, patch.ObservedUntilUnix)
	applyPatchField(&metadata.ObservedFailureCount, patch.ObservedFailures)
	if patch.ObservedGrace.Set {
		metadata.ObservedGraceEndpoints = append([]ObservedGraceEndpoint(nil), patch.ObservedGrace.Value...)
	}
	if patch.LastFailure.Set {
		metadata.LastFailure = clonePeerFailure(patch.LastFailure.Value)
	}
	if len(patch.Reject) > 0 && metadata.RejectedObjects == nil {
		metadata.RejectedObjects = make(map[zone.ZonePath]RejectedObject, len(patch.Reject))
	}
	for path, rejected := range patch.Reject {
		if !path.Valid() {
			continue
		}
		rejected.RootHash = append([]byte(nil), rejected.RootHash...)
		metadata.RejectedObjects[path] = rejected
	}
	for _, path := range patch.ClearRejected {
		delete(metadata.RejectedObjects, path)
	}
}

func applyPatchField[T any](target *T, field PatchField[T]) {
	if field.Set {
		*target = field.Value
	}
}

func clonePeerCheckpoint(metadata PeerCheckpoint) PeerCheckpoint {
	out := metadata
	out.LastFailure = clonePeerFailure(metadata.LastFailure)
	out.ObservedGraceEndpoints = append([]ObservedGraceEndpoint(nil), metadata.ObservedGraceEndpoints...)
	if metadata.RejectedObjects != nil {
		out.RejectedObjects = make(map[zone.ZonePath]RejectedObject, len(metadata.RejectedObjects))
		for path, rejected := range metadata.RejectedObjects {
			rejected.RootHash = append([]byte(nil), rejected.RootHash...)
			out.RejectedObjects[path] = rejected
		}
	}
	return out
}

func clonePeerFailure(failure *PeerFailure) *PeerFailure {
	if failure == nil {
		return nil
	}
	out := *failure
	return &out
}

func peerCheckpointEmpty(metadata PeerCheckpoint) bool {
	if len(metadata.ObservedGraceEndpoints) == 0 {
		metadata.ObservedGraceEndpoints = nil
	}
	if len(metadata.RejectedObjects) == 0 {
		metadata.RejectedObjects = nil
	}
	return reflect.DeepEqual(metadata, PeerCheckpoint{})
}

// RevokedPeerCheckpoints returns only revocation results and affected hints.
// The application decides cleanup policy; no network records or keys escape.
func (store *Store) RevokedPeerCheckpoints(now time.Time) (map[zone.ZonePath]bool, map[string]PeerCheckpoint) {
	if store == nil {
		return nil, nil
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.state == nil {
		return nil, nil
	}
	revoked := store.state.Network.RevokedZones(now)
	var peers map[string]PeerCheckpoint
	for id, peer := range store.gossip.Peers {
		if revoked[zone.ZonePath(id)] {
			if peers == nil {
				peers = make(map[string]PeerCheckpoint)
			}
			peers[id] = clonePeerCheckpoint(peer)
		}
	}
	return revoked, peers
}

// PeerCheckpoints returns detached hints for only the requested peers.
func (store *Store) PeerCheckpoints(ids []string) map[string]PeerCheckpoint {
	out := make(map[string]PeerCheckpoint, len(ids))
	if store == nil {
		return out
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	for _, id := range ids {
		if peer, ok := store.gossip.Peers[id]; ok {
			out[id] = clonePeerCheckpoint(peer)
		}
	}
	return out
}
