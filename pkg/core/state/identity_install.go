package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

var (
	ErrManagedZoneChange = errors.New("managed zone cannot change during identity install")
	ErrTrustedRootChange = errors.New("trusted root public key cannot change during identity install")
)

// IdentityInstall is the verified input accepted from a join bundle. Network
// contains the verified root-to-managed chain; IdentityPrivateKey remains raw
// local key material under the administrator's host security boundary.
type IdentityInstall struct {
	ManagedZone          zone.ZonePath
	Network              *zone.NetworkState
	TrustedRootPublicKey ed25519.PublicKey
	IdentityPrivateKey   ed25519.PrivateKey
}

// InstallIdentity initializes or refreshes the managed identity root. A
// refresh preserves locally owned zone content and unrelated learned zones,
// while replacing only authority/delegation envelopes supplied by the verified
// root-to-managed chain.
func (store *Store) InstallIdentity(ctx context.Context, install IdentityInstall, now time.Time) (CommitResult, error) {
	var out CommitResult
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

	candidate, err := prepareIdentityInstall(current, install, now)
	if err != nil {
		return out, err
	}
	if verifiedStateJSONEqual(current, candidate) {
		out.Changes.VerifiedRevision = baseRevision
		return out, nil
	}
	changedZones := identityChangedZones(current, candidate)
	nextRevision := baseRevision + 1
	changes := ChangeSet{
		VerifiedRevision: nextRevision,
		ChangedZones:     changedZones,
		NetworkChanged:   len(changedZones) > 0,
		SecurityPriority: true,
	}
	if store.commit != nil {
		if err := store.commit(ctx, cloneCommitCandidate(candidate, gossipCandidate), changes); err != nil {
			return CommitResult{}, err
		}
	}
	store.mu.Lock()
	store.state = candidate
	store.gossip = gossipCandidate
	store.revision = nextRevision
	store.mu.Unlock()
	return CommitResult{Committed: true, Changes: changes}, nil
}

func prepareIdentityInstall(current *VerifiedState, install IdentityInstall, now time.Time) (*VerifiedState, error) {
	if !install.ManagedZone.Valid() || install.Network == nil || len(install.IdentityPrivateKey) != ed25519.PrivateKeySize ||
		len(install.TrustedRootPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: incomplete identity install", ErrInvalidStateRoot)
	}
	if verifiedStateInitialized(current) {
		if current.ManagedZone != install.ManagedZone {
			return nil, fmt.Errorf("%w: current=%s requested=%s", ErrManagedZoneChange, current.ManagedZone, install.ManagedZone)
		}
		if len(current.TrustedRootPublicKey) != 0 && !bytes.Equal(current.TrustedRootPublicKey, install.TrustedRootPublicKey) {
			return nil, ErrTrustedRootChange
		}
	}
	incoming := &VerifiedState{
		ManagedZone:          install.ManagedZone,
		Network:              zone.CloneNetworkState(install.Network),
		TrustedRootPublicKey: append(ed25519.PublicKey(nil), install.TrustedRootPublicKey...),
		IdentityPrivateKey:   append(ed25519.PrivateKey(nil), install.IdentityPrivateKey...),
	}
	incoming.Network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	if err := validateInstalledIdentity(incoming, now); err != nil {
		return nil, err
	}
	if !verifiedStateInitialized(current) {
		return incoming, nil
	}
	merged, err := mergeIdentityNetwork(current.Network, incoming.Network)
	if err != nil {
		return nil, err
	}
	candidate := cloneVerifiedState(current)
	candidate.ManagedZone = install.ManagedZone
	candidate.Network = merged
	candidate.TrustedRootPublicKey = append(ed25519.PublicKey(nil), install.TrustedRootPublicKey...)
	candidate.IdentityPrivateKey = append(ed25519.PrivateKey(nil), install.IdentityPrivateKey...)
	if err := validateInstalledIdentity(candidate, now); err != nil {
		return nil, err
	}
	return candidate, nil
}

func verifiedStateInitialized(state *VerifiedState) bool {
	return state != nil && state.Network != nil && state.ManagedZone.Valid() && state.Network.Zones[state.ManagedZone] != nil
}

func validateInstalledIdentity(state *VerifiedState, now time.Time) error {
	if err := ValidateStateRoot(state); err != nil {
		return err
	}
	managed := state.Network.Zones[state.ManagedZone]
	identityPublic := state.IdentityPrivateKey.Public().(ed25519.PublicKey)
	if managed == nil || !managed.Authority.HasPublicKey(identityPublic) {
		return errors.New("identity private key is not authorized by the managed zone")
	}
	if err := photoncrypto.VerifyChain(state.Network, state.ManagedZone, now); err != nil {
		return err
	}
	return nil
}

func mergeIdentityNetwork(current, incoming *zone.NetworkState) (*zone.NetworkState, error) {
	merged := zone.CloneNetworkState(current)
	paths := make([]zone.ZonePath, 0, len(incoming.Zones))
	for path := range incoming.Zones {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i] < paths[j] })
	for _, path := range paths {
		source := incoming.Zones[path]
		if source == nil {
			continue
		}
		target := merged.Zones[path]
		if target == nil {
			cloned := zone.CloneNetworkStateForZone(incoming, path)
			merged.Zones[path] = cloned.Zones[path]
			continue
		}
		if target.Authority != nil && source.Authority != nil {
			currentHash := photoncrypto.AuthorityHash(target.Authority)
			nextHash := photoncrypto.AuthorityHash(source.Authority)
			switch {
			case source.Authority.Epoch < target.Authority.Epoch:
				return nil, fmt.Errorf("%w: zone=%s current=%d requested=%d", ErrAuthorityEpochStale, path, target.Authority.Epoch, source.Authority.Epoch)
			case source.Authority.Epoch == target.Authority.Epoch && !bytes.Equal(currentHash, nextHash):
				return nil, fmt.Errorf("%w: zone=%s epoch=%d", ErrAuthorityEpochConflict, path, target.Authority.Epoch)
			}
		}
		merged = zone.CloneNetworkStateForZone(merged, path)
		target = merged.Zones[path]
		target.Authority = cloneAuthority(source.Authority)
		target.ParentProof = cloneDelegations(source.ParentProof)
		ensureZoneCollections(target)
		for child, delegation := range source.Delegations {
			target.Delegations[child] = cloneDelegation(delegation)
		}
		for child, revocation := range source.Revocations {
			target.Revocations[child] = cloneRevocation(revocation)
		}
	}
	merged.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	return merged, nil
}

func cloneDelegations(values []*zone.Delegation) []*zone.Delegation {
	if values == nil {
		return nil
	}
	out := make([]*zone.Delegation, len(values))
	for i, value := range values {
		out[i] = cloneDelegation(value)
	}
	return out
}

func verifiedStateJSONEqual(left, right *VerifiedState) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func identityChangedZones(left, right *VerifiedState) []zone.ZonePath {
	paths := make(map[zone.ZonePath]struct{})
	if left != nil && left.Network != nil {
		for path := range left.Network.Zones {
			paths[path] = struct{}{}
		}
	}
	if right != nil && right.Network != nil {
		for path := range right.Network.Zones {
			paths[path] = struct{}{}
		}
	}
	out := make([]zone.ZonePath, 0, len(paths))
	for path := range paths {
		var leftZone, rightZone *zone.ZoneState
		if left != nil && left.Network != nil {
			leftZone = left.Network.Zones[path]
		}
		if right != nil && right.Network != nil {
			rightZone = right.Network.Zones[path]
		}
		leftJSON, leftErr := json.Marshal(leftZone)
		rightJSON, rightErr := json.Marshal(rightZone)
		if leftErr != nil || rightErr != nil || !bytes.Equal(leftJSON, rightJSON) {
			out = append(out, path)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
