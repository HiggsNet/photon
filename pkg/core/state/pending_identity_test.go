package state

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestNewPendingIdentityIsDetachedAndAuthorityless(t *testing.T) {
	root, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := NewPendingIdentity("node.catofes.", root, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateStateRoot(candidate.Verified); err != nil {
		t.Fatal(err)
	}
	if err := photoncrypto.VerifyPinnedRoot(candidate.Verified.Network, root); err != nil {
		t.Fatal(err)
	}
	managed := candidate.Verified.Network.Zones["node.catofes."]
	if managed.Authority != nil || len(managed.Records) != 0 || len(managed.ParentProof) != 0 || len(candidate.Verified.RootPrivateKey) != 0 || candidate.Gossip == nil {
		t.Fatal("pending root acquired authority or local publication")
	}
	wantPrivate := append([]byte(nil), private...)
	wantRoot := append([]byte(nil), root...)
	private[0] ^= 1
	root[0] ^= 1
	if !bytes.Equal(candidate.Verified.IdentityPrivateKey, wantPrivate) || !bytes.Equal(candidate.Verified.TrustedRootPublicKey, wantRoot) {
		t.Fatal("pending root retained key input aliases")
	}
	if err := photoncrypto.VerifyPinnedRoot(candidate.Verified.Network, wantRoot); err != nil {
		t.Fatal(err)
	}
}

func TestNewPendingIdentityRejectsInvalidInputs(t *testing.T) {
	root, _, _ := ed25519.GenerateKey(nil)
	_, private, _ := ed25519.GenerateKey(nil)
	badPrivate := append(ed25519.PrivateKey(nil), private...)
	badPrivate[63] ^= 1
	for _, tc := range []struct {
		managed zone.ZonePath
		root    ed25519.PublicKey
		private ed25519.PrivateKey
	}{
		{".", root, private}, {"invalid", root, private}, {"node.", nil, private}, {"node.", root, nil}, {"node.", root, badPrivate},
	} {
		if candidate, err := NewPendingIdentity(tc.managed, tc.root, tc.private); err == nil || candidate != nil {
			t.Fatalf("invalid inputs accepted: %s", tc.managed)
		}
	}
}
