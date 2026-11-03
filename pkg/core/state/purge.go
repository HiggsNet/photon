package state

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

// PurgeRevokedPlan contains only common-state deletions. Platform runtime
// cleanup (for example Linux IPsec links) is planned and executed by the
// platform controller from this zone set.
type PurgeRevokedPlan struct {
	Zones              []zone.ZonePath
	CheckpointPeers    []string
	ManagedZoneSkipped []zone.ZonePath
}

type PurgeRevokedResult struct {
	CommitResult
	Plan PurgeRevokedPlan
}

// PlanPurgeRevoked reports the common-state portion of an explicit revoked
// zone purge without changing memory or persistent state.
func (store *Store) PlanPurgeRevoked(now time.Time, target zone.ZonePath) (PurgeRevokedPlan, error) {
	if store == nil {
		return PurgeRevokedPlan{}, ErrVerifiedStoreClosed
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return PurgeRevokedPlan{}, ErrVerifiedStoreClosed
	}
	return planPurgeRevoked(store.state, store.gossip, now, target)
}

// PurgeRevoked removes revoked verified zone bodies and their loss-tolerant
// gossip checkpoints. Parent revocation tombstones and the local identity
// chain are retained. Persistence completes before the new root is published.
func (store *Store) PurgeRevoked(ctx context.Context, now time.Time, target zone.ZonePath) (PurgeRevokedResult, error) {
	var out PurgeRevokedResult
	if store == nil {
		return out, ErrVerifiedStoreClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	store.writeMu.Lock()
	defer store.writeMu.Unlock()

	store.mu.RLock()
	if store.closed {
		store.mu.RUnlock()
		return out, ErrVerifiedStoreClosed
	}
	baseRevision := store.VerifiedRevision()
	candidate := cloneVerifiedState(store.state)
	gossipCandidate := cloneGossipCheckpoint(store.gossip)
	store.mu.RUnlock()

	plan, err := planPurgeRevoked(candidate, gossipCandidate, now, target)
	if err != nil {
		return out, err
	}
	out.Plan = clonePurgeRevokedPlan(plan)
	for _, path := range plan.Zones {
		delete(candidate.Network.Zones, path)
	}
	for _, peerID := range plan.CheckpointPeers {
		delete(gossipCandidate.Peers, peerID)
	}
	networkChanged := len(plan.Zones) > 0
	checkpointChanged := len(plan.CheckpointPeers) > 0
	if !networkChanged && !checkpointChanged {
		out.Changes.VerifiedRevision = baseRevision
		return out, nil
	}
	nextRevision := baseRevision
	if networkChanged {
		nextRevision++
	}
	changes := ChangeSet{
		VerifiedRevision:        nextRevision,
		ChangedZones:            append([]zone.ZonePath(nil), plan.Zones...),
		NetworkChanged:          networkChanged,
		GossipCheckpointChanged: checkpointChanged,
		SecurityPriority:        true,
	}
	if store.commit != nil {
		if err := store.commit(ctx, cloneCommitCandidate(candidate, gossipCandidate), changes); err != nil {
			return PurgeRevokedResult{}, err
		}
	}
	store.mu.Lock()
	store.state = candidate
	store.gossip = gossipCandidate
	store.revision.Store(uint64(nextRevision))
	store.mu.Unlock()
	out.Committed = true
	out.Changes = changes
	return out, nil
}

func planPurgeRevoked(state *VerifiedState, gossip *GossipCheckpoint, now time.Time, target zone.ZonePath) (PurgeRevokedPlan, error) {
	plan := PurgeRevokedPlan{}
	if state == nil || state.Network == nil {
		return plan, nil
	}
	candidates := make(map[zone.ZonePath]bool)
	if target == "" {
		for path := range state.Network.Zones {
			if path != zone.RootZone && state.Network.IsZoneRevoked(path, now) {
				candidates[path] = true
			}
		}
	} else {
		if !target.Valid() || target == zone.RootZone {
			return plan, fmt.Errorf("invalid purge zone: %s", target)
		}
		if !state.Network.IsZoneRevoked(target, now) {
			return plan, fmt.Errorf("zone is not revoked: %s", target)
		}
		if overlapsManagedIdentity(target, state.ManagedZone) {
			return plan, fmt.Errorf("refusing to purge local identity zone: %s", target)
		}
		candidates[target] = true
		for path := range state.Network.Zones {
			if isDescendantZone(path, target) {
				candidates[path] = true
			}
		}
	}
	for path := range candidates {
		if overlapsManagedIdentity(path, state.ManagedZone) {
			plan.ManagedZoneSkipped = append(plan.ManagedZoneSkipped, path)
			delete(candidates, path)
		}
	}
	for path := range candidates {
		if state.Network.Zones[path] != nil {
			plan.Zones = append(plan.Zones, path)
		}
	}
	if gossip != nil {
		for peerID := range gossip.Peers {
			if candidates[zone.ZonePath(peerID)] {
				plan.CheckpointPeers = append(plan.CheckpointPeers, peerID)
			}
		}
	}
	sort.Slice(plan.Zones, func(i, j int) bool { return plan.Zones[i] < plan.Zones[j] })
	sort.Strings(plan.CheckpointPeers)
	sort.Slice(plan.ManagedZoneSkipped, func(i, j int) bool { return plan.ManagedZoneSkipped[i] < plan.ManagedZoneSkipped[j] })
	return plan, nil
}

func overlapsManagedIdentity(path, managed zone.ZonePath) bool {
	if !path.Valid() || !managed.Valid() {
		return false
	}
	return path == managed || isDescendantZone(managed, path)
}

func isDescendantZone(path, parent zone.ZonePath) bool {
	if !path.Valid() || !parent.Valid() || path == parent {
		return false
	}
	for _, ancestor := range path.Ancestors() {
		if ancestor == parent {
			return true
		}
	}
	return false
}

func clonePurgeRevokedPlan(value PurgeRevokedPlan) PurgeRevokedPlan {
	return PurgeRevokedPlan{
		Zones:              append([]zone.ZonePath(nil), value.Zones...),
		CheckpointPeers:    append([]string(nil), value.CheckpointPeers...),
		ManagedZoneSkipped: append([]zone.ZonePath(nil), value.ManagedZoneSkipped...),
	}
}
