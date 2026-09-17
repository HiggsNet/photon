package crypto

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

// ConfiguredRootAuthority is the protocol's immutable root trust anchor. Root
// key rotation intentionally requires a new network. Its sole key is implicitly
// privileged, so future permissions do not alter this authority's hash.
func ConfiguredRootAuthority(publicKey ed25519.PublicKey) *zone.ZoneAuthority {
	return &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key: append(ed25519.PublicKey(nil), publicKey...),
		}},
	}
}

// VerifyPinnedRoot requires the exact immutable root authority derived from the pin.
func VerifyPinnedRoot(ns *zone.NetworkState, trusted ed25519.PublicKey) error {
	if len(trusted) != ed25519.PublicKeySize {
		return errors.New("trusted root public key must be an Ed25519 public key")
	}
	if ns == nil {
		return errors.New("trusted root public key configured but network state is nil")
	}
	root := ns.Zones[zone.RootZone]
	if root == nil || root.Authority == nil {
		return errors.New("trusted root public key configured but root authority is missing")
	}
	if bytes.Equal(AuthorityHash(root.Authority), AuthorityHash(ConfiguredRootAuthority(trusted))) {
		return nil
	}
	return errors.New("root authority does not match immutable trusted_root_public_key authority")
}

// RepairLegacyRootAuthority repairs only the old bootstrap capability shape at startup.
// A different key, epoch, threshold or key count is never adopted.
func RepairLegacyRootAuthority(ns *zone.NetworkState, trusted ed25519.PublicKey) bool {
	if ns == nil || len(trusted) != ed25519.PublicKeySize {
		return false
	}
	root := ns.Zones[zone.RootZone]
	if root == nil || root.Authority == nil {
		return false
	}
	a := root.Authority
	if a.Zone == zone.RootZone && a.Epoch == 1 && a.Threshold == SupportedThreshold && len(a.Keys) == 1 && bytes.Equal(a.Keys[0].Key, trusted) && len(a.Keys[0].Capabilities) > 0 {
		root.Authority = ConfiguredRootAuthority(trusted)
		return true
	}
	return false
}
