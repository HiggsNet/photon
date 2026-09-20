package gossip

import (
	"crypto/ed25519"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestDiagnoseAutoJoinAdoptionNotPending(t *testing.T) {
	verified := pendingAdmissionState(t, "node-b.catofes.", true)
	network, result, err := corestate.ReconcileManagedAuthority(
		verified.Network, verified.ManagedZone, verified.IdentityPrivateKey.Public().(ed25519.PublicKey), time.Unix(1000, 0),
	)
	if err != nil || !result.Adopted {
		t.Fatalf("pre-adopt: result=%+v err=%v", result, err)
	}
	verified.Network = network
	now := time.Unix(2000, 0)
	d := DiagnoseAutoJoinAdmission(verified, nil, nil, now)
	if d.Pending {
		t.Fatalf("diagnosis should not be pending after adoption")
	}
	if d.Reason != AdmissionReasonAdopted {
		t.Fatalf("reason = %s, want adopted or not_applicable", d.Reason)
	}
}

func TestDiagnoseAutoJoinMissingParentZone(t *testing.T) {
	verified := pendingAdmissionState(t, "node-b.catofes.", true)
	delete(verified.Network.Zones, verified.ManagedZone.Parent())
	now := time.Unix(1000, 0)
	d := DiagnoseAutoJoinAdmission(verified, nil, nil, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != AdmissionReasonMissingParentZone {
		t.Fatalf("reason = %s, want %s", d.Reason, AdmissionReasonMissingParentZone)
	}
}

func TestDiagnoseAutoJoinMissingDelegation(t *testing.T) {
	verified := pendingAdmissionState(t, "node-b.catofes.", true)
	parent := verified.ManagedZone.Parent()
	parentState := verified.Network.Zones[parent]
	if parentState == nil {
		t.Fatalf("parent zone missing")
	}
	delete(parentState.Delegations, verified.ManagedZone)
	now := time.Unix(1000, 0)
	d := DiagnoseAutoJoinAdmission(verified, nil, nil, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != AdmissionReasonMissingDelegation {
		t.Fatalf("reason = %s, want %s", d.Reason, AdmissionReasonMissingDelegation)
	}
}

func TestDiagnoseAutoJoinDelegationKeyMismatch(t *testing.T) {
	verified := pendingAdmissionState(t, "node-b.catofes.", false)
	now := time.Unix(1000, 0)
	d := DiagnoseAutoJoinAdmission(verified, nil, nil, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != AdmissionReasonDelegationKeyMismatch {
		t.Fatalf("reason = %s, want %s", d.Reason, AdmissionReasonDelegationKeyMismatch)
	}
}

func TestDiagnoseAutoJoinNoBootstrapSync(t *testing.T) {
	verified := pendingAdmissionState(t, "node-b.catofes.", true)
	now := time.Unix(1000, 0)
	checkpoint := &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{
		"unrelated.catofes.": {LastSyncUnix: now.Add(-time.Minute).Unix()},
	}}
	d := DiagnoseAutoJoinAdmission(verified, checkpoint, []string{"catofes."}, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != AdmissionReasonNoBootstrapSync {
		t.Fatalf("reason = %s, want %s", d.Reason, AdmissionReasonNoBootstrapSync)
	}
}

func TestDiagnoseAutoJoinWaitingForAdoption(t *testing.T) {
	verified := pendingAdmissionState(t, "node-b.catofes.", true)
	now := time.Unix(1000, 0)
	checkpoint := &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{
		"catofes.": {LastSyncUnix: now.Add(-5 * time.Minute).Unix()},
	}}
	d := DiagnoseAutoJoinAdmission(verified, checkpoint, []string{"catofes."}, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != AdmissionReasonWaitingForAdoption {
		t.Fatalf("reason = %s, want %s", d.Reason, AdmissionReasonWaitingForAdoption)
	}
}

func TestDiagnoseAutoJoinJoinRequestPresent(t *testing.T) {
	verified := pendingAdmissionState(t, "node-b.catofes.", true)
	now := time.Unix(1000, 0)
	d := DiagnoseAutoJoinAdmission(verified, nil, nil, now)
	if d.JoinRequestB64 == "" {
		t.Fatalf("join_request should be present for pending state with key")
	}
	if !d.HasZonePrivateKey {
		t.Fatalf("has_zone_private_key should be true")
	}
}

func pendingAdmissionState(t *testing.T, managed zone.ZonePath, matchingDelegation bool) *corestate.VerifiedState {
	t.Helper()
	pub, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !matchingDelegation {
		pub, _, err = ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	parentPub, parentPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(parent): %v", err)
	}
	parent := managed.Parent()
	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite},
			}},
		}},
	}
	parentAuthority := &zone.ZoneAuthority{
		Zone:      parent,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: parentPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite},
			}},
		}},
	}
	childAuthority := &zone.ZoneAuthority{
		Zone:      managed,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite, zone.PermDelegate},
			}},
		}},
	}
	parentDelegation := &zone.Delegation{
		ZoneName:  parent,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *parentAuthority,
	}
	if err := photoncrypto.SignDelegation(parentDelegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation(parent): %v", err)
	}
	childDelegation := &zone.Delegation{
		ZoneName:  managed,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *childAuthority,
	}
	if err := photoncrypto.SignDelegation(childDelegation, parent, parentPriv); err != nil {
		t.Fatalf("SignDelegation(child): %v", err)
	}
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	ns.Zones[zone.RootZone].Delegations[parent] = parentDelegation
	ns.Zones[parent] = zone.NewZoneState(parent, parentAuthority)
	ns.Zones[parent].ParentProof = []*zone.Delegation{parentDelegation}
	ns.Zones[parent].Delegations[managed] = childDelegation
	ns.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	return &corestate.VerifiedState{
		ManagedZone:        managed,
		IdentityPrivateKey: privateKey,
		Network:            ns,
	}
}

func TestAdmissionBoundaryStates(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, tc := range []struct {
		name    string
		change  func(*corestate.VerifiedState)
		reason  string
		pending bool
	}{
		{"empty network", func(s *corestate.VerifiedState) { s.Network = nil }, AdmissionReasonMissingParentZone, true},
		{"missing private key", func(s *corestate.VerifiedState) { s.IdentityPrivateKey = nil }, AdmissionReasonMissingZoneKey, true},
		{"missing parent authority", func(s *corestate.VerifiedState) { s.Network.Zones[s.ManagedZone.Parent()].Authority = nil }, AdmissionReasonMissingParentZone, true},
		{"invalid signature", func(s *corestate.VerifiedState) {
			s.Network.Zones[s.ManagedZone.Parent()].Delegations[s.ManagedZone].Signature[0] ^= 1
		}, AdmissionReasonVerifyDelegationFailed, true},
		{"expired delegation", func(s *corestate.VerifiedState) {
			s.Network.Zones[s.ManagedZone.Parent()].Delegations[s.ManagedZone].ExpiresAt = &now
		}, AdmissionReasonVerifyDelegationFailed, true},
		{"root", func(s *corestate.VerifiedState) { s.ManagedZone = zone.RootZone }, AdmissionReasonNotApplicable, false},
		{"invalid zone", func(s *corestate.VerifiedState) { s.ManagedZone = "invalid" }, AdmissionReasonNotApplicable, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := pendingAdmissionState(t, "node-b.catofes.", true)
			tc.change(s)
			d := DiagnoseAutoJoinAdmission(s, nil, nil, now)
			if d.Reason != tc.reason || d.Pending != tc.pending {
				t.Fatalf("diagnosis = %+v", d)
			}
		})
	}
	if d := DiagnoseAutoJoinAdmission(nil, nil, nil, now); d != (AdmissionDiagnosis{}) {
		t.Fatalf("nil state diagnosis = %+v", d)
	}
}
