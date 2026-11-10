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
