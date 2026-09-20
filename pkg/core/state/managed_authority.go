package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

// RefreshManagedAuthority commits a newer parent-owned authority envelope for
// the managed zone while preserving its locally owned contents.
func (store *Store) RefreshManagedAuthority(ctx context.Context, now time.Time) (CommitResult, ManagedAuthorityResult, error) {
	var commit CommitResult
	var authority ManagedAuthorityResult
	if store == nil {
		return commit, authority, ErrVerifiedStoreClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	store.writeMu.Lock()
	defer store.writeMu.Unlock()
	store.mu.RLock()
	if store.closed {
		store.mu.RUnlock()
		return commit, authority, ErrVerifiedStoreClosed
	}
	baseRevision := store.revision
	current := cloneVerifiedState(store.state)
	gossipCandidate := cloneGossipCheckpoint(store.gossip)
	store.mu.RUnlock()
	var publicKey []byte
	if len(current.IdentityPrivateKey) == ed25519.PrivateKeySize {
		publicKey = current.IdentityPrivateKey.Public().(ed25519.PublicKey)
	}
	network, authority, err := ReconcileManagedAuthority(current.Network, current.ManagedZone, publicKey, now)
	if err != nil {
		return commit, authority, err
	}
	if !authority.Adopted && !authority.Refreshed {
		commit.Changes.VerifiedRevision = baseRevision
		return commit, authority, nil
	}
	candidate := cloneVerifiedState(current)
	candidate.Network = network
	if err := ValidateStateRoot(candidate); err != nil {
		return CommitResult{}, ManagedAuthorityResult{}, err
	}
	nextRevision := baseRevision + 1
	changes := ChangeSet{VerifiedRevision: nextRevision, ChangedZones: []zone.ZonePath{candidate.ManagedZone}, NetworkChanged: true, SecurityPriority: true}
	if store.commit != nil {
		if err := store.commit(ctx, cloneCommitCandidate(candidate, gossipCandidate), changes); err != nil {
			return CommitResult{}, ManagedAuthorityResult{}, err
		}
	}
	store.mu.Lock()
	store.state = candidate
	store.gossip = gossipCandidate
	store.revision = nextRevision
	store.mu.Unlock()
	return CommitResult{Committed: true, Changes: changes}, authority, nil
}

type ManagedAuthorityResult struct {
	Adopted   bool
	Refreshed bool
}

// ReconcileManagedAuthority adopts or refreshes the parent-owned authority
// envelope for managed while retaining locally owned records, delegations,
// revocations and history. It never mutates network.
func ReconcileManagedAuthority(network *zone.NetworkState, managed zone.ZonePath, identityPublicKey []byte, now time.Time) (*zone.NetworkState, ManagedAuthorityResult, error) {
	var result ManagedAuthorityResult
	if network == nil {
		return nil, result, errors.New("network state is nil")
	}
	if !managed.Valid() || managed == zone.RootZone {
		return network, result, nil
	}
	parent := managed.Parent()
	parentState := network.Zones[parent]
	if parentState == nil || parentState.Authority == nil {
		return network, result, nil
	}
	delegation := parentState.Delegations[managed]
	if delegation == nil {
		return network, result, nil
	}
	if delegation.ZoneName != managed || delegation.Authority.Zone != managed {
		return network, result, fmt.Errorf("managed zone delegation target mismatch: %s", managed)
	}
	if err := photoncrypto.VerifyChain(network, parent, now); err != nil {
		return network, result, fmt.Errorf("verify managed zone parent %s: %w", parent, err)
	}
	if err := photoncrypto.VerifyDelegation(delegation, parentState.Authority, parent, now); err != nil {
		return network, result, err
	}
	current := network.Zones[managed]
	if current == nil || current.Authority == nil {
		if len(identityPublicKey) != ed25519.PublicKeySize || !delegation.Authority.HasPublicKey(identityPublicKey) {
			return network, result, nil
		}
		candidate := zone.CloneNetworkStateForZone(network, managed)
		managedState := zone.NewZoneState(managed, cloneAuthority(&delegation.Authority))
		managedState.ParentProof = []*zone.Delegation{cloneDelegation(delegation)}
		candidate.Zones[managed] = managedState
		candidate.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
		if err := photoncrypto.VerifyChain(candidate, managed, now); err != nil {
			return network, result, err
		}
		result.Adopted = true
		return candidate, result, nil
	}

	currentEpoch := current.Authority.Epoch
	nextEpoch := delegation.Authority.Epoch
	currentHash := photoncrypto.AuthorityHash(current.Authority)
	nextHash := delegation.AuthorityHash
	switch {
	case nextEpoch < currentEpoch:
		return network, result, fmt.Errorf("managed zone delegation epoch %d is older than local authority epoch %d", nextEpoch, currentEpoch)
	case nextEpoch == currentEpoch && !bytes.Equal(nextHash, currentHash):
		return network, result, fmt.Errorf("managed zone authority conflicts at epoch %d", currentEpoch)
	case nextEpoch == currentEpoch:
		return network, result, nil
	}
	if len(identityPublicKey) != ed25519.PublicKeySize {
		return network, result, errors.New("managed zone authority refresh requires a local identity public key")
	}
	if !delegation.Authority.HasPublicKey(identityPublicKey) {
		return network, result, errors.New("managed zone authority refresh does not authorize the local identity key")
	}

	candidate := zone.CloneNetworkStateForZone(network, managed)
	managedState := candidate.Zones[managed]
	managedState.Authority = cloneAuthority(&delegation.Authority)
	managedState.ParentProof = replaceManagedParentProof(managedState.ParentProof, managed, delegation)
	candidate.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	if err := photoncrypto.VerifyChain(candidate, managed, now); err != nil {
		return network, result, err
	}
	result.Refreshed = true
	return candidate, result, nil
}

func replaceManagedParentProof(existing []*zone.Delegation, managed zone.ZonePath, delegation *zone.Delegation) []*zone.Delegation {
	out := make([]*zone.Delegation, 0, len(existing)+1)
	out = append(out, cloneDelegation(delegation))
	for _, proof := range existing {
		if proof == nil || proof.ZoneName == managed {
			continue
		}
		out = append(out, cloneDelegation(proof))
	}
	return out
}
