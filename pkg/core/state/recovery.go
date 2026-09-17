package state

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

var ErrRecoveryRootChange = errors.New("recovery snapshot cannot replace the unpinned root authority")

// RecoveryImport is an explicit, administrator-requested snapshot import. It
// may restore the managed zone, unlike ordinary peer synchronization, but it
// cannot change the persisted trust anchor.
type RecoveryImport struct {
	Snapshot *ZoneSnapshot
	Limits   SyncLimits
}

type RecoveryImportResult struct {
	CommitResult
	Apply *ApplyResult
}

// ImportRecoverySnapshot verifies and commits one recovery snapshot. The
// candidate is persisted before it becomes visible through ReadView.
func (store *Store) ImportRecoverySnapshot(ctx context.Context, input RecoveryImport, now time.Time) (RecoveryImportResult, error) {
	var out RecoveryImportResult
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
	baseRevision := store.revision
	current := cloneVerifiedState(store.state)
	gossipCandidate := cloneGossipCheckpoint(store.gossip)
	store.mu.RUnlock()

	if err := validateRecoveryRootSnapshot(current, input.Snapshot); err != nil {
		return out, err
	}
	nextNetwork, applied, err := ApplyRecoverySnapshot(current.Network, input.Snapshot, now, input.Limits)
	if err != nil {
		return out, err
	}
	candidate := cloneVerifiedState(current)
	candidate.Network = nextNetwork
	if err := ValidateStateRoot(candidate); err != nil {
		return out, err
	}
	out.Apply = cloneApplyResult(applied)
	if verifiedStateJSONEqual(current, candidate) {
		out.Changes.VerifiedRevision = baseRevision
		if out.Apply != nil {
			out.Apply.NetworkChanged = false
		}
		return out, nil
	}

	nextRevision := baseRevision + 1
	changes := ChangeSet{
		VerifiedRevision: nextRevision,
		ChangedZones:     []zone.ZonePath{input.Snapshot.Zone},
		NetworkChanged:   true,
		SecurityPriority: true,
	}
	if store.commit != nil {
		if err := store.commit(ctx, cloneCommitCandidate(candidate, gossipCandidate), changes); err != nil {
			return RecoveryImportResult{}, err
		}
	}
	store.mu.Lock()
	store.state = candidate
	store.gossip = gossipCandidate
	store.revision = nextRevision
	store.mu.Unlock()
	out.Committed = true
	out.Changes = changes
	if out.Apply != nil {
		out.Apply.NetworkChanged = true
	}
	return out, nil
}

func validateRecoveryRootSnapshot(current *VerifiedState, snapshot *ZoneSnapshot) error {
	if snapshot == nil {
		return errors.New("recovery snapshot is nil")
	}
	if snapshot.Zone != zone.RootZone {
		return nil
	}
	if snapshot.Authority == nil {
		return errors.New("root recovery snapshot has no authority")
	}
	if len(current.TrustedRootPublicKey) != 0 {
		probe := zone.NewNetworkState()
		probe.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, cloneAuthority(snapshot.Authority))
		if err := photoncrypto.VerifyPinnedRoot(probe, current.TrustedRootPublicKey); err != nil {
			return fmt.Errorf("root recovery snapshot does not match trusted root: %w", err)
		}
		return nil
	}
	root := current.Network.Zones[zone.RootZone]
	if root == nil || root.Authority == nil || !bytes.Equal(
		photoncrypto.AuthorityHash(root.Authority),
		photoncrypto.AuthorityHash(snapshot.Authority),
	) {
		return ErrRecoveryRootChange
	}
	return nil
}

func cloneApplyResult(value *ApplyResult) *ApplyResult {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
