package state

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

// NewPendingIdentity constructs the shared auto-join root. The stable local
// signing identity has no managed authority until verified Gossip adoption.
// It grants no delegation, record-writing permission or network ownership.
func NewPendingIdentity(managed zone.ZonePath, trustedRoot ed25519.PublicKey, private ed25519.PrivateKey) (*CommitCandidate, error) {
	if !managed.Valid() || managed.IsRoot() {
		return nil, errors.New("pending identity requires a non-root managed zone")
	}
	if len(trustedRoot) != ed25519.PublicKeySize {
		return nil, errors.New("pending identity requires a trusted root public key")
	}
	if len(private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(private[:ed25519.SeedSize]), private) {
		return nil, errors.New("pending identity private key is invalid")
	}
	network := zone.NewNetworkState()
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, photoncrypto.ConfiguredRootAuthority(trustedRoot))
	network.Zones[managed] = zone.NewZoneState(managed, nil)
	network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	candidate := &CommitCandidate{Verified: &VerifiedState{
		ManagedZone: managed, Network: network,
		TrustedRootPublicKey: append(ed25519.PublicKey(nil), trustedRoot...),
		IdentityPrivateKey:   append(ed25519.PrivateKey(nil), private...),
	}, Gossip: &GossipCheckpoint{}}
	if err := ValidateStateRoot(candidate.Verified); err != nil {
		return nil, err
	}
	return candidate, nil
}
