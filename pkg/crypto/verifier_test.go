package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestVerifierSignatureTupleAndOwnership(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	payload := []byte("photon.record:complete domain-separated payload")
	signature := ed25519.Sign(private, payload)
	originalPublic, originalPayload, originalSignature := bytes.Clone(public), bytes.Clone(payload), bytes.Clone(signature)
	v := new(Verifier)
	if !v.verifySignature(public, payload, signature) || len(v.signatures) != 1 {
		t.Fatal("valid signature not retained")
	}
	for _, input := range [][]byte{public, payload, signature} {
		input[0] ^= 1
		if v.verifySignature(public, payload, signature) {
			t.Fatal("changed public key, domain payload or signature hit memo")
		}
		input[0] ^= 1
	}
	clear(public)
	clear(payload)
	clear(signature)
	if !v.verifySignature(originalPublic, originalPayload, originalSignature) || len(v.signatures) != 1 {
		t.Fatal("caller buffers changed retained tuple")
	}
	for key := range v.signatures {
		if !bytes.Equal(key.public[:], originalPublic) || key.payload != string(originalPayload) || !bytes.Equal(key.signature[:], originalSignature) {
			t.Fatal("memo retained caller-owned bytes")
		}
	}
	for _, verifier := range []*Verifier{nil, v} {
		if verifier.verifySignature(nil, originalPayload, originalSignature) || verifier.verifySignature(originalPublic, originalPayload, nil) {
			t.Fatal("malformed key or signature accepted")
		}
	}
}

func TestVerifierBoundsAndSuccessOnly(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	for _, size := range []int{8, verifierMaxPayload} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			v := new(Verifier)
			payload := make([]byte, size)
			for n := 0; n <= verifierMaxEntries; n++ {
				binary.BigEndian.PutUint64(payload, uint64(n))
				signature := ed25519.Sign(private, payload)
				if !v.verifySignature(public, payload, signature) {
					t.Fatal("valid signature rejected at capacity")
				}
				if len(v.signatures) > verifierMaxEntries || v.bytes > verifierMaxBytes {
					t.Fatal("memo budget exceeded")
				}
				count, retained := len(v.signatures), v.bytes
				signature[0] ^= 1
				if v.verifySignature(public, payload, signature) || len(v.signatures) != count || v.bytes != retained {
					t.Fatal("failure retained or displaced successful memo entries")
				}
			}
			if len(v.signatures) == verifierMaxEntries {
				t.Fatal("full memo was not bounded by eviction")
			}
		})
	}
	v := new(Verifier)
	payload := make([]byte, verifierMaxPayload+1)
	if !v.verifySignature(public, payload, ed25519.Sign(private, payload)) || len(v.signatures) != 0 || v.bytes != 0 {
		t.Fatal("oversized valid payload must verify without being retained")
	}
}

func verifierRecordFixture(t *testing.T) (*zone.Record, *zone.ZoneAuthority, time.Time) {
	t.Helper()
	public, private, _ := ed25519.GenerateKey(nil)
	a := &zone.ZoneAuthority{Zone: "node.catofes.", Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: public, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite}, KeyPrefix: "data/"}}}}}
	r := &zone.Record{Zone: a.Zone, Key: "data/one", Type: "test", Value: []byte("original"), Version: 1, Timestamp: 100}
	if err := SignRecord(r, private); err != nil {
		t.Fatal(err)
	}
	return r, a, time.Unix(100, 100)
}

func TestVerifierWarmSignatureDoesNotAuthorizeRecord(t *testing.T) {
	for _, scenario := range []string{"capability", "key-prefix", "expired-key", "future-key", "threshold", "value", "value-and-hash", "signed-fields", "signature"} {
		t.Run(scenario, func(t *testing.T) {
			r, a, now := verifierRecordFixture(t)
			v := new(Verifier)
			if err := v.VerifyRecord(r, a, now); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "capability":
				a.Keys[0].Capabilities = nil
			case "key-prefix":
				a.Keys[0].Capabilities[0].KeyPrefix = "other/"
			case "expired-key":
				a.Keys[0].NotAfter = now.Unix() - 1
			case "future-key":
				a.Keys[0].NotBefore = now.Unix() + 1
			case "threshold":
				a.Threshold = 2
			case "value":
				r.Value[0] ^= 1
			case "value-and-hash":
				r.Value[0] ^= 1
				r.ValueHash = Hash(r.Value)
			case "signed-fields":
				r.Version++
			case "signature":
				r.Signature[0] ^= 1
			}
			plain, cached := VerifyRecord(r, a, now), v.VerifyRecord(r, a, now)
			if plain == nil || cached == nil || plain.Error() != cached.Error() {
				t.Fatalf("warm signature changed rejection: plain=%v cached=%v", plain, cached)
			}
			if len(v.signatures) != 1 {
				t.Fatal("invalid record entered memo")
			}
		})
	}
}

func TestVerifierKeyTimeBoundariesRemainLive(t *testing.T) {
	r, a, now := verifierRecordFixture(t)
	a.Keys[0].NotBefore, a.Keys[0].NotAfter = 100, 100
	v := new(Verifier)
	for _, at := range []time.Time{now, time.Unix(100, 999999999), time.Unix(101, 0), time.Unix(99, 999999999), now} {
		plain, cached := VerifyRecord(r, a, at), v.VerifyRecord(r, a, at)
		if (plain == nil) != (cached == nil) {
			t.Fatalf("cached key validity differs at %v", at)
		}
	}
}

func TestVerifierChainStillChecksExpiryAndRevocation(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	childPublic, _, _ := ed25519.GenerateKey(nil)
	root := ConfiguredRootAuthority(public)
	child := &zone.ZoneAuthority{Zone: "child.", Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: childPublic, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite}}}}}}
	expires := time.Unix(100, 500000000)
	d := &zone.Delegation{ZoneName: child.Zone, Authority: *child, ExpiresAt: &expires}
	if err := SignDelegation(d, zone.RootZone, private); err != nil {
		t.Fatal(err)
	}
	network := zone.NewNetworkState()
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, root)
	network.Zones[zone.RootZone].Delegations[child.Zone] = d
	network.Zones[child.Zone] = zone.NewZoneState(child.Zone, child)
	v := new(Verifier)
	if err := v.VerifyChain(network, child.Zone, expires.Add(-time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyChain(network, child.Zone, expires); err == nil {
		t.Fatal("warm delegation accepted at exact sub-second expiry")
	}
	// Revocation's mathematical signature may be warm at a later time, but
	// moving the clock back must still reject its not-yet-active semantics.
	r := &zone.DelegationRevocation{ChildZone: child.Zone, ParentZone: zone.RootZone, RevokedAuthorityEpoch: d.AuthorityEpoch, RevokedAuthorityHash: bytes.Clone(d.AuthorityHash), RevokedAt: 100}
	if err := SignDelegationRevocation(r, zone.RootZone, private); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyDelegationRevocation(r, root, zone.RootZone, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyDelegationRevocation(r, root, zone.RootZone, time.Unix(99, 999999999)); err == nil {
		t.Fatal("warm future revocation accepted after clock rollback")
	}
	network.Zones[zone.RootZone].Revocations[child.Zone] = r
	if err := v.VerifyChain(network, child.Zone, time.Unix(100, 0)); !errors.Is(err, zone.ErrZoneRevoked) {
		t.Fatalf("warm chain bypassed new revocation: %v", err)
	}
}
