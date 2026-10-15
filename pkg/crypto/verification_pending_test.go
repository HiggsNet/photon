package crypto

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func requireVerificationPending(t *testing.T, err error, message string) {
	t.Helper()
	var pending VerificationPendingError
	if !errors.As(fmt.Errorf("wrapped verification: %w", err), &pending) || err.Error() != message {
		t.Fatalf("pending classification/text changed: %v", err)
	}
}

func requireVerificationDefinite(t *testing.T, err error) {
	t.Helper()
	var pending VerificationPendingError
	if err == nil || errors.As(err, &pending) {
		t.Fatalf("definite failure classified pending: %v", err)
	}
}

func TestVerificationPendingRevocationWaitsForTimeWithoutAcceptingBadSignature(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	authority := ConfiguredRootAuthority(public)
	revocation := &zone.DelegationRevocation{ChildZone: "child.", ParentZone: zone.RootZone, RevokedAuthorityEpoch: 1, RevokedAuthorityHash: []byte("revoked-authority"), RevokedAt: 101}
	if err := SignDelegationRevocation(revocation, zone.RootZone, private); err != nil {
		t.Fatal(err)
	}
	for _, verifier := range []*Verifier{nil, new(Verifier)} {
		requireVerificationPending(t, verifier.VerifyDelegationRevocation(revocation, authority, zone.RootZone, time.Unix(100, 999999999)), "revocation is not active yet")
		if err := verifier.VerifyDelegationRevocation(revocation, authority, zone.RootZone, time.Unix(101, 0)); err != nil {
			t.Fatal(err)
		}
		requireVerificationPending(t, verifier.VerifyDelegationRevocation(revocation, authority, zone.RootZone, time.Unix(100, 0)), "revocation is not active yet")
		revocation.Signature[0] ^= 1
		requireVerificationDefinite(t, verifier.VerifyDelegationRevocation(revocation, authority, zone.RootZone, time.Unix(101, 0)))
		revocation.Signature[0] ^= 1
	}
}

func TestVerificationPendingKeyWaitsForTimeButExpiryCapabilityAndSignatureStayDefinite(t *testing.T) {
	for _, verifier := range []*Verifier{nil, new(Verifier)} {
		record, authority, _ := verifierRecordFixture(t)
		authority.Keys[0].NotBefore, authority.Keys[0].NotAfter = 101, 102
		requireVerificationPending(t, verifier.VerifyRecord(record, authority, time.Unix(100, 0)), "authorized key not yet valid")
		if err := verifier.VerifyRecord(record, authority, time.Unix(101, 0)); err != nil {
			t.Fatal(err)
		}
		requireVerificationDefinite(t, verifier.VerifyRecord(record, authority, time.Unix(103, 0)))
		record.Signature[0] ^= 1
		requireVerificationDefinite(t, verifier.VerifyRecord(record, authority, time.Unix(101, 0)))
		record.Signature[0] ^= 1
		authority.Keys[0].Capabilities = nil
		requireVerificationDefinite(t, verifier.VerifyRecord(record, authority, time.Unix(101, 0)))
	}
}

func TestVerificationPendingChainDependenciesRecoverWithoutChangingChild(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	childPublic, _, _ := ed25519.GenerateKey(nil)
	root := ConfiguredRootAuthority(public)
	child := &zone.ZoneAuthority{Zone: "child.", Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: childPublic}}}
	delegation := &zone.Delegation{ZoneName: child.Zone, Authority: *child}
	if err := SignDelegation(delegation, zone.RootZone, private); err != nil {
		t.Fatal(err)
	}
	network := zone.NewNetworkState()
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, root)
	requireVerificationPending(t, VerifyChain(network, child.Zone, time.Unix(100, 0)), "zone not found")
	network.Zones[child.Zone] = zone.NewZoneState(child.Zone, nil)
	requireVerificationPending(t, VerifyChain(network, child.Zone, time.Unix(100, 0)), "zone authority is nil")
	network.Zones[child.Zone].Authority = child
	requireVerificationPending(t, VerifyChain(network, child.Zone, time.Unix(100, 0)), "delegation not found")
	network.Zones[zone.RootZone].Delegations[child.Zone] = delegation
	if err := VerifyChain(network, child.Zone, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	delegation.Signature[0] ^= 1
	requireVerificationDefinite(t, VerifyChain(network, child.Zone, time.Unix(100, 0)))
	delegation.Signature[0] ^= 1
	otherRoot, _, _ := ed25519.GenerateKey(nil)
	requireVerificationDefinite(t, VerifyPinnedRoot(network, otherRoot))
	network.Zones[zone.RootZone].Authority = nil
	requireVerificationDefinite(t, VerifyChain(network, child.Zone, time.Unix(100, 0)))
}

func TestVerificationPendingMissingParentAuthority(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(nil)
	root := ConfiguredRootAuthority(public)
	network := zone.NewNetworkState()
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, root)
	network.Zones["child.parent."] = zone.NewZoneState("child.parent.", &zone.ZoneAuthority{Zone: "child.parent.", Threshold: 1})
	requireVerificationPending(t, VerifyChain(network, "child.parent.", time.Unix(100, 0)), "parent zone authority is nil")
	record, _, now := verifierRecordFixture(t)
	requireVerificationDefinite(t, VerifyRecord(record, nil, now))
	requireVerificationDefinite(t, VerifyChain(network, "invalid", now))
	requireVerificationDefinite(t, VerifyChain(zone.NewNetworkState(), zone.RootZone, now))
}
