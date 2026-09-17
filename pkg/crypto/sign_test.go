package crypto

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestSignAndVerifyRecord(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	authority := &zone.ZoneAuthority{
		Zone:      "node1.catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
				KeyPrefix:   "wireguard/",
			}},
		}},
	}

	record := &zone.Record{
		Zone:      "node1.catofes.",
		Key:       "wireguard/public_key",
		Type:      "wireguard.public_key",
		Value:     []byte("wg-pubkey"),
		Version:   1,
		Timestamp: 123,
	}

	if err := SignRecord(record, priv); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := VerifyRecord(record, authority, time.Unix(123, 0)); err != nil {
		t.Fatalf("VerifyRecord: %v", err)
	}

	record.Value = []byte("tampered")
	if err := VerifyRecord(record, authority, time.Unix(123, 0)); err == nil {
		t.Fatalf("VerifyRecord accepted tampered value")
	}
}

func TestRootKeyHasImplicitPermissionsWithoutCapabilities(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	authority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys:      []zone.AuthorizedKey{{Key: pub}},
	}
	record := &zone.Record{
		Zone:      zone.RootZone,
		Key:       "ipam/pools/10.0.0.0_8",
		Type:      "ipam.pool",
		Value:     []byte("pool"),
		Version:   1,
		Timestamp: 123,
	}
	if err := SignRecord(record, priv); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := VerifyRecord(record, authority, time.Unix(123, 0)); err != nil {
		t.Fatalf("VerifyRecord(root implicit permission): %v", err)
	}
}

func TestVerifyRecordRejectsPrePhotonDomainSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	authority := &zone.ZoneAuthority{
		Zone:      "node1.catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}
	record := &zone.Record{
		Zone:      "node1.catofes.",
		Key:       "identity",
		Type:      "node.identity",
		Value:     []byte("node1"),
		Version:   1,
		Timestamp: 123,
		ValueHash: Hash([]byte("node1")),
		SignedBy:  append([]byte(nil), pub...),
	}
	var legacy builder
	legacy.str("higgs.record.v1")
	legacy.str(record.Zone.String())
	legacy.str(record.Key)
	legacy.str(record.Type)
	legacy.bytes(record.ValueHash)
	legacy.u64(record.Version)
	legacy.bytes(record.PrevHash)
	legacy.i64(record.Timestamp)
	legacy.bytes(KeyID(record.SignedBy))
	record.Signature = ed25519.Sign(priv, legacy.out)

	if err := VerifyRecord(record, authority, time.Unix(123, 0)); err == nil {
		t.Fatal("VerifyRecord accepted a pre-Photon domain signature")
	}
}

func TestVerifyRecordRejectsTamperedSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	authority := &zone.ZoneAuthority{
		Zone:      "node1.catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}
	record := &zone.Record{
		Zone:      "node1.catofes.",
		Key:       "identity",
		Type:      "node.identity",
		Value:     []byte("node1"),
		Version:   1,
		Timestamp: 123,
	}
	if err := SignRecord(record, priv); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}

	record.Signature[0] ^= 0xff
	if err := VerifyRecord(record, authority, time.Unix(123, 0)); err == nil {
		t.Fatalf("VerifyRecord accepted tampered signature")
	}
}

func TestVerifyRecordRejectsExpiredAuthorityKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	record := &zone.Record{
		Zone:      "node1.catofes.",
		Key:       "identity",
		Type:      "node.identity",
		Value:     []byte("node1"),
		Version:   1,
		Timestamp: 123,
	}
	if err := SignRecord(record, priv); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}

	err = VerifyRecord(record, &zone.ZoneAuthority{
		Zone:      "node1.catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key:      pub,
			NotAfter: 122,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}, time.Unix(123, 0))
	if err == nil {
		t.Fatalf("VerifyRecord accepted expired authority key")
	}
}

func TestVerifyRecordRejectsUnsupportedThreshold(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	record := &zone.Record{
		Zone:      "node1.catofes.",
		Key:       "identity",
		Type:      "node.identity",
		Value:     []byte("node1"),
		Version:   1,
		Timestamp: 123,
	}
	if err := SignRecord(record, priv); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}

	err = VerifyRecord(record, &zone.ZoneAuthority{
		Zone:      "node1.catofes.",
		Epoch:     1,
		Threshold: 2,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}, time.Unix(123, 0))
	if !errors.Is(err, ErrUnsupportedThreshold) {
		t.Fatalf("VerifyRecord error = %v, want ErrUnsupportedThreshold", err)
	}
}

func TestSignAndVerifyDelegation(t *testing.T) {
	parentPub, parentPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(parent): %v", err)
	}
	childPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(child): %v", err)
	}

	parentAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: parentPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}

	delegation := &zone.Delegation{
		ZoneName: "node1.catofes.",
		Scope:    zone.DelegationScopeDirectChild,
		Authority: zone.ZoneAuthority{
			Zone:      "node1.catofes.",
			Epoch:     1,
			Threshold: 1,
			Keys: []zone.AuthorizedKey{{
				Key: childPub,
				Capabilities: []zone.Capability{{
					Permissions: []zone.Permission{zone.PermWrite},
				}},
			}},
		},
	}

	if err := SignDelegation(delegation, "catofes.", parentPriv); err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}
	if err := VerifyDelegation(delegation, parentAuthority, "catofes.", time.Unix(123, 0)); err != nil {
		t.Fatalf("VerifyDelegation: %v", err)
	}
}

func TestVerifyDelegationRejectsTamperedAuthority(t *testing.T) {
	parentPub, parentPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(parent): %v", err)
	}
	childPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(child): %v", err)
	}
	parentAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: parentPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	delegation := &zone.Delegation{
		ZoneName: "node1.catofes.",
		Scope:    zone.DelegationScopeDirectChild,
		Authority: zone.ZoneAuthority{
			Zone:      "node1.catofes.",
			Epoch:     1,
			Threshold: 1,
			Keys: []zone.AuthorizedKey{{
				Key: childPub,
				Capabilities: []zone.Capability{{
					Permissions: []zone.Permission{zone.PermWrite},
				}},
			}},
		},
	}
	if err := SignDelegation(delegation, "catofes.", parentPriv); err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}

	delegation.Authority.Keys[0].Capabilities[0].Permissions = []zone.Permission{zone.PermDelegate}
	if err := VerifyDelegation(delegation, parentAuthority, "catofes.", time.Unix(123, 0)); err == nil {
		t.Fatalf("VerifyDelegation accepted tampered authority")
	}
}

func TestVerifyDelegationRejectsSubtreeScopeInPhase0(t *testing.T) {
	parentPub, parentPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(parent): %v", err)
	}
	childPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(child): %v", err)
	}

	parentAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: parentPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	delegation := &zone.Delegation{
		ZoneName: "node1.pek.catofes.",
		Scope:    zone.DelegationScopeSubtree,
		Authority: zone.ZoneAuthority{
			Zone:      "node1.pek.catofes.",
			Epoch:     1,
			Threshold: 1,
			Keys: []zone.AuthorizedKey{{
				Key: childPub,
				Capabilities: []zone.Capability{{
					Permissions: []zone.Permission{zone.PermWrite},
				}},
			}},
		},
	}

	if err := SignDelegation(delegation, "catofes.", parentPriv); err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}
	err = VerifyDelegation(delegation, parentAuthority, "catofes.", time.Unix(123, 0))
	if !errors.Is(err, ErrUnsupportedDelegationScope) {
		t.Fatalf("VerifyDelegation error = %v, want ErrUnsupportedDelegationScope", err)
	}
}

func TestVerifyChain(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	childPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(child): %v", err)
	}

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	childAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: childPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}
	delegation := &zone.Delegation{
		ZoneName:  "catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *childAuthority,
	}
	if err := SignDelegation(delegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}

	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", childAuthority)
	ns.Zones[zone.RootZone].Delegations["catofes."] = delegation

	if err := VerifyChain(ns, "catofes.", time.Unix(123, 0)); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

func TestVerifyChainRejectsWrongRootKey(t *testing.T) {
	_, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root signer): %v", err)
	}
	wrongRootPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(wrong root): %v", err)
	}
	childPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(child): %v", err)
	}

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: wrongRootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	childAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: childPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}
	delegation := &zone.Delegation{
		ZoneName:  "catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *childAuthority,
	}
	if err := SignDelegation(delegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}

	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", childAuthority)
	ns.Zones[zone.RootZone].Delegations["catofes."] = delegation

	if err := VerifyChain(ns, "catofes.", time.Unix(123, 0)); err == nil {
		t.Fatalf("VerifyChain accepted delegation signed by an untrusted root key")
	}
}

func TestVerifyRecordIPAMRequiresAllocateIPCapability(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	record := &zone.Record{
		Zone:      "catofes.",
		Key:       "ipam/pools/10.0.0.0_16",
		Type:      "ipam.pool",
		Value:     []byte(`{"version":1,"prefix":"10.0.0.0/16","delegated_to":"catofes."}`),
		Version:   1,
		Timestamp: 123,
	}
	if err := SignRecord(record, priv); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}

	// Authority with PermAllocateIP should accept the pool record.
	authorityWithPerm := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermAllocateIP},
			}},
		}},
	}
	if err := VerifyRecord(record, authorityWithPerm, time.Unix(123, 0)); err != nil {
		t.Fatalf("VerifyRecord with PermAllocateIP: %v", err)
	}

	// Authority with only PermDelegate should reject the pool record.
	authorityWithoutPerm := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	if err := VerifyRecord(record, authorityWithoutPerm, time.Unix(123, 0)); err == nil {
		t.Fatalf("VerifyRecord accepted ipam.pool without PermAllocateIP")
	}
}

func TestVerifyRecordIPAMAssignmentRequiresAllocateIPCapability(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	record := &zone.Record{
		Zone:      "catofes.",
		Key:       "ipam/assignments/10.0.0.0_24",
		Type:      "ipam.assignment",
		Value:     []byte(`{"version":1,"prefix":"10.0.0.0/24","assigned_to":"pek.catofes."}`),
		Version:   1,
		Timestamp: 123,
	}
	if err := SignRecord(record, priv); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}

	authorityWithPerm := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermAllocateIP},
			}},
		}},
	}
	if err := VerifyRecord(record, authorityWithPerm, time.Unix(123, 0)); err != nil {
		t.Fatalf("VerifyRecord with PermAllocateIP: %v", err)
	}

	authorityWithoutPerm := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	if err := VerifyRecord(record, authorityWithoutPerm, time.Unix(123, 0)); err == nil {
		t.Fatalf("VerifyRecord accepted ipam.assignment without PermAllocateIP")
	}
}

func TestVerifyRecordServiceRequiresGeneralWriteCapability(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	record := &zone.Record{
		Zone: "node-a.catofes.", Key: "services/egress", Type: "service.socks5.v1",
		Value:   []byte(`{"type":"socks5","region":"cn-east","address":"fd42::20","port":1080}`),
		Version: 1, Timestamp: 123,
	}
	if err := SignRecord(record, priv); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	authority := func(permission zone.Permission) *zone.ZoneAuthority {
		return &zone.ZoneAuthority{Zone: record.Zone, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{
			Key: pub, Capabilities: []zone.Capability{{Permissions: []zone.Permission{permission}}},
		}}}
	}
	if err := VerifyRecord(record, authority(zone.PermAllocateIP), time.Unix(123, 0)); err == nil {
		t.Fatal("VerifyRecord accepted service record without write")
	}
	if err := VerifyRecord(record, authority(zone.PermWrite), time.Unix(123, 0)); err != nil {
		t.Fatalf("VerifyRecord with general write: %v", err)
	}
}
