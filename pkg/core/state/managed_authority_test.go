package state

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestReconcileManagedAuthorityAdoptsMatchingDelegation(t *testing.T) {
	now := time.Unix(1000, 0)
	network, identityPublic, _, _ := managedAuthorityFixture(t, false)
	candidate, result, err := ReconcileManagedAuthority(network, "node-a.catofes.", identityPublic, now)
	if err != nil {
		t.Fatalf("ReconcileManagedAuthority: %v", err)
	}
	if !result.Adopted || result.Refreshed {
		t.Fatalf("result = %+v, want adopted", result)
	}
	if network.Zones["node-a.catofes."] != nil {
		t.Fatal("reconcile mutated source network")
	}
	managed := candidate.Zones["node-a.catofes."]
	if managed == nil || managed.Authority == nil || len(managed.ParentProof) != 1 {
		t.Fatalf("managed zone = %#v", managed)
	}
	if err := photoncrypto.VerifyChain(candidate, "node-a.catofes.", now); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

func TestStoreApplyRemoteBatchRefreshesAuthorityAndRetainsLocalContents(t *testing.T) {
	now := time.Unix(1000, 0)
	initial, _, identityPrivate, parentPrivate := managedAuthorityFixture(t, true)
	initial.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	local := signedRecord(t, identityPrivate, "node-a.catofes.", "local", []byte("retained"), 1, nil, now.Unix())
	if err := initial.PutAt(local, now); err != nil {
		t.Fatalf("PutAt(local): %v", err)
	}
	initial.Zones["node-a.catofes."].Delegations["leaf.node-a.catofes."] = &zone.Delegation{ZoneName: "leaf.node-a.catofes."}

	source := cloneNetworkState(initial)
	parent := source.Zones["catofes."]
	refreshedAuthority := cloneAuthority(source.Zones["node-a.catofes."].Authority)
	refreshedAuthority.Epoch = 2
	refreshed := &zone.Delegation{
		ZoneName:  "node-a.catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *refreshedAuthority,
	}
	if err := photoncrypto.SignDelegation(refreshed, "catofes.", parentPrivate); err != nil {
		t.Fatalf("SignDelegation(refresh): %v", err)
	}
	parent.Delegations["node-a.catofes."] = refreshed
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot(parent): %v", err)
	}

	store := NewStore(&VerifiedState{
		ManagedZone:        "node-a.catofes.",
		Network:            initial,
		IdentityPrivateKey: identityPrivate,
	}, nil, nil)
	result, err := store.ApplyRemoteBatch(context.Background(), "peer-a", []RemoteSnapshot{{
		Snapshot:     snapshot,
		ExpectedRoot: ZoneRoot(ZoneStateFromSnapshot(snapshot)),
	}}, now)
	if err != nil {
		t.Fatalf("ApplyRemoteBatch: %v", err)
	}
	if len(result.Outcomes) != 1 || result.Outcomes[0].Err != nil || !result.Outcomes[0].AuthorityRefreshed {
		t.Fatalf("outcome = %#v, want authority refresh", result.Outcomes)
	}
	view := store.ReadView()
	managed := view.State.Network.Zones["node-a.catofes."]
	if managed.Authority.Epoch != 2 {
		t.Fatalf("managed authority epoch = %d, want 2", managed.Authority.Epoch)
	}
	if record := managed.Records["local"]; record == nil || string(record.Value) != "retained" {
		t.Fatalf("local record = %#v, want retained", record)
	}
	if managed.Delegations["leaf.node-a.catofes."] == nil {
		t.Fatal("managed authority refresh dropped local child delegation")
	}
	if len(managed.ParentProof) != 1 || managed.ParentProof[0].AuthorityEpoch != 2 {
		t.Fatalf("managed parent proof = %#v, want refreshed epoch 2 proof", managed.ParentProof)
	}
	if initial.Zones["node-a.catofes."].Authority.Epoch != 1 {
		t.Fatal("store refresh mutated retained initial network")
	}
	if len(result.Changes.ChangedZones) != 2 {
		t.Fatalf("changed zones = %#v, want parent and managed", result.Changes.ChangedZones)
	}
}

func TestStoreApplyRemoteBatchRejectsManagedAuthorityRefreshForDifferentKey(t *testing.T) {
	now := time.Unix(1000, 0)
	initial, _, identityPrivate, parentPrivate := managedAuthorityFixture(t, true)
	remote := cloneNetworkState(initial)
	otherPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(other): %v", err)
	}
	nextAuthority := cloneAuthority(remote.Zones["node-a.catofes."].Authority)
	nextAuthority.Epoch = 2
	nextAuthority.Keys[0].Key = otherPublic
	delegation := &zone.Delegation{ZoneName: "node-a.catofes.", Scope: zone.DelegationScopeDirectChild, Authority: *nextAuthority}
	if err := photoncrypto.SignDelegation(delegation, "catofes.", parentPrivate); err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}
	remote.Zones["catofes."].Delegations["node-a.catofes."] = delegation
	snapshot, err := Snapshot(remote, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot(parent): %v", err)
	}

	store := NewStore(&VerifiedState{ManagedZone: "node-a.catofes.", Network: initial, IdentityPrivateKey: identityPrivate}, nil, nil)
	result, err := store.ApplyRemoteBatch(context.Background(), "peer-a", []RemoteSnapshot{{
		Snapshot:     snapshot,
		ExpectedRoot: ZoneRoot(ZoneStateFromSnapshot(snapshot)),
	}}, now)
	if err != nil {
		t.Fatalf("ApplyRemoteBatch: %v", err)
	}
	if len(result.Outcomes) != 1 || result.Outcomes[0].Err == nil || result.Changes.NetworkChanged {
		t.Fatalf("outcome = %#v changes = %#v, want rejected network candidate", result.Outcomes, result.Changes)
	}
	view := store.ReadView()
	if got := view.State.Network.Zones["node-a.catofes."].Authority.Epoch; got != 1 {
		t.Fatalf("managed authority epoch = %d, want 1", got)
	}
	if got := view.State.Network.Zones["catofes."].Delegations["node-a.catofes."].AuthorityEpoch; got != 1 {
		t.Fatalf("parent delegation epoch = %d, want 1", got)
	}
	if err := photoncrypto.VerifyChain(view.State.Network, "node-a.catofes.", now); err != nil {
		t.Fatalf("VerifyChain after rejection: %v", err)
	}
}

func TestReconcileManagedAuthorityIgnoresIdentityMismatch(t *testing.T) {
	network, _, _, _ := managedAuthorityFixture(t, false)
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(other): %v", err)
	}
	candidate, result, err := ReconcileManagedAuthority(network, "node-a.catofes.", other, time.Unix(1000, 0))
	if err != nil || result != (ManagedAuthorityResult{}) || candidate != network {
		t.Fatalf("mismatch candidate/result/error = %p/%+v/%v", candidate, result, err)
	}
}

func TestReconcileManagedAuthorityRejectsRefreshIdentityMismatch(t *testing.T) {
	network, identityPublic, _, parentPrivate := managedAuthorityFixture(t, true)
	otherPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(other): %v", err)
	}
	nextAuthority := cloneAuthority(network.Zones["node-a.catofes."].Authority)
	nextAuthority.Epoch = 2
	nextAuthority.Keys[0].Key = otherPublic
	delegation := &zone.Delegation{ZoneName: "node-a.catofes.", Scope: zone.DelegationScopeDirectChild, Authority: *nextAuthority}
	if err := photoncrypto.SignDelegation(delegation, "catofes.", parentPrivate); err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}
	network.Zones["catofes."].Delegations["node-a.catofes."] = delegation

	candidate, result, err := ReconcileManagedAuthority(network, "node-a.catofes.", identityPublic, time.Unix(1000, 0))
	if err == nil || result != (ManagedAuthorityResult{}) || candidate != network {
		t.Fatalf("refresh mismatch candidate/result/error = %p/%+v/%v", candidate, result, err)
	}
	if network.Zones["node-a.catofes."].Authority.Epoch != 1 {
		t.Fatal("failed refresh mutated managed authority")
	}
}

func managedAuthorityFixture(t *testing.T, includeManaged bool) (*zone.NetworkState, ed25519.PublicKey, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	parentPublic, parentPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(parent): %v", err)
	}
	identityPublic, identityPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(identity): %v", err)
	}
	authority := func(path zone.ZonePath, public ed25519.PublicKey, permissions ...zone.Permission) *zone.ZoneAuthority {
		return &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{
			Key:          public,
			Capabilities: []zone.Capability{{Permissions: permissions}},
		}}}
	}
	rootAuthority := authority(zone.RootZone, rootPublic, zone.PermDelegate, zone.PermWrite)
	parentAuthority := authority("catofes.", parentPublic, zone.PermDelegate, zone.PermWrite)
	managedAuthority := authority("node-a.catofes.", identityPublic, zone.PermDelegate, zone.PermWrite)
	parentDelegation := &zone.Delegation{ZoneName: "catofes.", Scope: zone.DelegationScopeDirectChild, Authority: *parentAuthority}
	if err := photoncrypto.SignDelegation(parentDelegation, zone.RootZone, rootPrivate); err != nil {
		t.Fatalf("SignDelegation(parent): %v", err)
	}
	managedDelegation := &zone.Delegation{ZoneName: "node-a.catofes.", Scope: zone.DelegationScopeDirectChild, Authority: *managedAuthority}
	if err := photoncrypto.SignDelegation(managedDelegation, "catofes.", parentPrivate); err != nil {
		t.Fatalf("SignDelegation(managed): %v", err)
	}

	network := zone.NewNetworkState()
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	network.Zones[zone.RootZone].Delegations["catofes."] = parentDelegation
	network.Zones["catofes."] = zone.NewZoneState("catofes.", parentAuthority)
	network.Zones["catofes."].ParentProof = []*zone.Delegation{cloneDelegation(parentDelegation)}
	network.Zones["catofes."].Delegations["node-a.catofes."] = managedDelegation
	if includeManaged {
		network.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", managedAuthority)
		network.Zones["node-a.catofes."].ParentProof = []*zone.Delegation{cloneDelegation(managedDelegation)}
	}
	network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	return network, identityPublic, identityPrivate, parentPrivate
}
