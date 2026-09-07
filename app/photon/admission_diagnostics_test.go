package main

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestDiagnoseAutoJoinAdoptionNotPending(t *testing.T) {
	dir := t.TempDir()
	verified, _, _ := buildPendingAutoJoinOwners(t, dir, "node-b.catofes.", true)
	network, result, err := corestate.ReconcileManagedAuthority(
		verified.Network, verified.ManagedZone, verified.IdentityPrivateKey.Public().(ed25519.PublicKey), time.Unix(1000, 0),
	)
	if err != nil || !result.Adopted {
		t.Fatalf("pre-adopt: result=%+v err=%v", result, err)
	}
	verified.Network = network
	now := time.Unix(2000, 0)
	d := diagnoseAutoJoinAdmission(verified, nil, nil, now)
	if d.Pending {
		t.Fatalf("diagnosis should not be pending after adoption")
	}
	if d.Reason != inspect.AdmissionReasonAdopted && d.Reason != inspect.AdmissionReasonNotApplicable {
		t.Fatalf("reason = %s, want adopted or not_applicable", d.Reason)
	}
}

func TestDiagnoseAutoJoinMissingParentZone(t *testing.T) {
	dir := t.TempDir()
	verified, _, _ := buildPendingAutoJoinOwners(t, dir, "node-b.catofes.", true)
	delete(verified.Network.Zones, verified.ManagedZone.Parent())
	now := time.Unix(1000, 0)
	d := diagnoseAutoJoinAdmission(verified, nil, nil, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != inspect.AdmissionReasonMissingParentZone {
		t.Fatalf("reason = %s, want %s", d.Reason, inspect.AdmissionReasonMissingParentZone)
	}
}

func TestDiagnoseAutoJoinMissingDelegation(t *testing.T) {
	dir := t.TempDir()
	verified, _, _ := buildPendingAutoJoinOwners(t, dir, "node-b.catofes.", true)
	parent := verified.ManagedZone.Parent()
	parentState := verified.Network.Zones[parent]
	if parentState == nil {
		t.Fatalf("parent zone missing")
	}
	delete(parentState.Delegations, verified.ManagedZone)
	now := time.Unix(1000, 0)
	d := diagnoseAutoJoinAdmission(verified, nil, nil, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != inspect.AdmissionReasonMissingDelegation {
		t.Fatalf("reason = %s, want %s", d.Reason, inspect.AdmissionReasonMissingDelegation)
	}
}

func TestDiagnoseAutoJoinDelegationKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	verified, _, _ := buildPendingAutoJoinOwners(t, dir, "node-b.catofes.", false)
	now := time.Unix(1000, 0)
	d := diagnoseAutoJoinAdmission(verified, nil, nil, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != inspect.AdmissionReasonDelegationKeyMismatch {
		t.Fatalf("reason = %s, want %s", d.Reason, inspect.AdmissionReasonDelegationKeyMismatch)
	}
}

func TestDiagnoseAutoJoinNoBootstrapSync(t *testing.T) {
	dir := t.TempDir()
	verified, _, _ := buildPendingAutoJoinOwners(t, dir, "node-b.catofes.", true)
	now := time.Unix(1000, 0)
	checkpoint := &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{
		"unrelated.catofes.": {LastSyncUnix: now.Add(-time.Minute).Unix()},
	}}
	d := diagnoseAutoJoinAdmission(verified, checkpoint, []syncConfigPeer{{ID: "catofes."}}, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != inspect.AdmissionReasonNoBootstrapSync {
		t.Fatalf("reason = %s, want %s", d.Reason, inspect.AdmissionReasonNoBootstrapSync)
	}
}

func TestDiagnoseAutoJoinWaitingForAdoption(t *testing.T) {
	dir := t.TempDir()
	verified, _, _ := buildPendingAutoJoinOwners(t, dir, "node-b.catofes.", true)
	now := time.Unix(1000, 0)
	checkpoint := &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{
		"catofes.": {LastSyncUnix: now.Add(-5 * time.Minute).Unix()},
	}}
	d := diagnoseAutoJoinAdmission(verified, checkpoint, []syncConfigPeer{{ID: "catofes."}}, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != inspect.AdmissionReasonWaitingForAdoption {
		t.Fatalf("reason = %s, want %s", d.Reason, inspect.AdmissionReasonWaitingForAdoption)
	}
}

func TestDiagnoseAutoJoinJoinRequestPresent(t *testing.T) {
	dir := t.TempDir()
	verified, _, _ := buildPendingAutoJoinOwners(t, dir, "node-b.catofes.", true)
	now := time.Unix(1000, 0)
	d := diagnoseAutoJoinAdmission(verified, nil, nil, now)
	if d.JoinRequestB64 == "" {
		t.Fatalf("join_request should be present for pending state with key")
	}
	if !d.HasZonePrivateKey {
		t.Fatalf("has_zone_private_key should be true")
	}
}
