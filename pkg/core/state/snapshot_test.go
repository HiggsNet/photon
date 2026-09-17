package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/vmihailenco/msgpack/v5"
)

func cloneNetworkState(ns *zone.NetworkState) *zone.NetworkState {
	if ns == nil {
		return zone.NewNetworkState()
	}
	return zone.CloneNetworkState(ns)
}

func TestApplySnapshotVerifiesAndMergesWholeZone(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePriv := testNetwork(t)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)

	v1 := signedRecord(t, zonePriv, "catofes.", "identity", []byte("node-a"), 1, nil, now.Unix())
	if err := source.PutAt(v1, now); err != nil {
		t.Fatalf("PutAt(v1): %v", err)
	}
	v2 := signedRecord(t, zonePriv, "catofes.", "identity", []byte("node-b"), 2, photoncrypto.RecordHash(v1), now.Unix()+1)
	if err := source.PutAt(v2, now); err != nil {
		t.Fatalf("PutAt(v2): %v", err)
	}

	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snapshot.RecordHistory) != 0 {
		t.Fatalf("snapshot history len = %d, want 0", len(snapshot.RecordHistory))
	}

	target := cloneNetworkState(source)
	target.Zones["catofes."].Records = make(map[string]*zone.Record)
	target.Zones["catofes."].RecordHistory = make(map[string][]*zone.Record)
	target.Zones["catofes."].Records["obsolete"] = signedRecord(t, zonePriv, "catofes.", "obsolete", []byte("old"), 1, nil, now.Unix())
	result, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits())
	if err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	if result.Records != 1 {
		t.Fatalf("applied records = %d, want 1", result.Records)
	}
	got := target.Zones["catofes."].Records["identity"]
	if got == nil || string(got.Value) != "node-b" || got.Version != 2 {
		t.Fatalf("active record = %#v, want v2", got)
	}
	if target.Zones["catofes."].Records["obsolete"] == nil {
		t.Fatalf("trusted local key was removed by whole-zone snapshot")
	}
}

func TestApplySnapshotTrustFailureLeavesNetworkUnchanged(t *testing.T) {
	now := time.Unix(1000, 0)
	source, _ := testNetwork(t)
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	untrustedPublicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(untrusted): %v", err)
	}
	snapshot.Authority.Keys[0].Key = untrustedPublicKey

	target := snapshotAtomicityTarget(source)
	before := captureNetworkState(t, target)
	if _, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits()); !errors.Is(err, ErrUntrustedZone) {
		t.Fatalf("ApplySnapshot = %v, want ErrUntrustedZone", err)
	}
	assertNetworkStateUnchanged(t, target, before)
}

func TestApplySnapshotDelegationFailureLeavesNetworkUnchanged(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePrivateKey := testNetwork(t)
	childPublicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(child): %v", err)
	}
	childAuthority := zone.ZoneAuthority{
		Zone:      "node-a.catofes.",
		Epoch:     1,
		Threshold: photoncrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key: childPublicKey,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}
	delegation := &zone.Delegation{
		ZoneName:  childAuthority.Zone,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: childAuthority,
	}
	if err := photoncrypto.SignDelegation(delegation, "catofes.", zonePrivateKey); err != nil {
		t.Fatalf("SignDelegation(child): %v", err)
	}
	delegation.Signature[0] ^= 0xff

	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	snapshot.Delegations[delegation.ZoneName] = delegation

	target := snapshotAtomicityTarget(source)
	before := captureNetworkState(t, target)
	if _, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits()); err == nil {
		t.Fatal("ApplySnapshot succeeded with an invalid delegation")
	}
	assertNetworkStateUnchanged(t, target, before)
}

func TestApplySnapshotRevocationFailureLeavesNetworkUnchanged(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePrivateKey := testNetwork(t)
	revocation := &zone.DelegationRevocation{
		ChildZone:             "node-a.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: 1,
		RevokedAuthorityHash:  []byte("child-authority"),
		Reason:                "test",
		RevokedAt:             now.Unix(),
	}
	if err := photoncrypto.SignDelegationRevocation(revocation, "catofes.", zonePrivateKey); err != nil {
		t.Fatalf("SignDelegationRevocation(child): %v", err)
	}
	revocation.Signature[0] ^= 0xff

	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	snapshot.Revocations[revocation.ChildZone] = revocation

	target := snapshotAtomicityTarget(source)
	before := captureNetworkState(t, target)
	if _, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits()); err == nil {
		t.Fatal("ApplySnapshot succeeded with an invalid revocation")
	}
	assertNetworkStateUnchanged(t, target, before)
}

func TestApplySnapshotRecordFailureAfterSuccessLeavesNetworkUnchanged(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePrivateKey := testNetwork(t)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	first := signedRecord(t, zonePrivateKey, "catofes.", "a-valid", []byte("first"), 1, nil, now.Unix())
	if err := source.PutAt(first, now); err != nil {
		t.Fatalf("PutAt(first): %v", err)
	}
	second := signedRecord(t, zonePrivateKey, "catofes.", "z-invalid", []byte("second"), 1, nil, now.Unix())
	if err := source.PutAt(second, now); err != nil {
		t.Fatalf("PutAt(second): %v", err)
	}
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	snapshot.Records["z-invalid"].Signature[0] ^= 0xff

	target := snapshotAtomicityTarget(source)
	delete(target.Zones["catofes."].Records, "a-valid")
	delete(target.Zones["catofes."].Records, "z-invalid")
	before := captureNetworkState(t, target)
	if _, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits()); err == nil {
		t.Fatal("ApplySnapshot succeeded with an invalid second record")
	}
	assertNetworkStateUnchanged(t, target, before)
}

func TestApplySnapshotSkipsStaleAndConflictingRecords(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePrivateKey := testNetwork(t)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	stale := signedRecord(t, zonePrivateKey, "catofes.", "stale", []byte("remote-v1"), 1, nil, now.Unix())
	conflict := signedRecord(t, zonePrivateKey, "catofes.", "conflict", []byte("remote"), 1, nil, now.Unix())
	if err := source.PutAt(stale, now); err != nil {
		t.Fatalf("PutAt(stale): %v", err)
	}
	if err := source.PutAt(conflict, now); err != nil {
		t.Fatalf("PutAt(conflict): %v", err)
	}
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	target := cloneNetworkState(source)
	target.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	targetStaleV1 := signedRecord(t, zonePrivateKey, "catofes.", "stale", []byte("local-v1"), 1, nil, now.Unix())
	targetStaleV2 := signedRecord(t, zonePrivateKey, "catofes.", "stale", []byte("local-v2"), 2, photoncrypto.RecordHash(targetStaleV1), now.Unix()+1)
	target.Zones["catofes."].Records["stale"] = targetStaleV2
	target.Zones["catofes."].Records["conflict"] = signedRecord(t, zonePrivateKey, "catofes.", "conflict", []byte("local"), 1, nil, now.Unix())

	result, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits())
	if err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	if result.Records != 0 {
		t.Fatalf("applied records = %d, want 0", result.Records)
	}
	if got := string(target.Zones["catofes."].Records["stale"].Value); got != "local-v2" {
		t.Fatalf("stale record = %q, want local-v2", got)
	}
	if got := string(target.Zones["catofes."].Records["conflict"].Value); got != "local" {
		t.Fatalf("conflicting record = %q, want local", got)
	}
}

func TestApplySnapshotSuccessInstallsDetachedCandidate(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePrivateKey := testNetwork(t)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	v1 := signedRecord(t, zonePrivateKey, "catofes.", "identity", []byte("v1"), 1, nil, now.Unix())
	if err := source.PutAt(v1, now); err != nil {
		t.Fatalf("PutAt(v1): %v", err)
	}
	target := cloneNetworkState(source)
	target.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	target.Zones[zone.RootZone].RecordHistory = nil
	previousTargetZone := target.Zones["catofes."]

	v2 := signedRecord(t, zonePrivateKey, "catofes.", "identity", []byte("v2"), 2, photoncrypto.RecordHash(v1), now.Unix()+1)
	if err := source.PutAt(v2, now); err != nil {
		t.Fatalf("PutAt(v2): %v", err)
	}
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	result, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits())
	if err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	if result.Records != 1 {
		t.Fatalf("applied records = %d, want 1", result.Records)
	}
	if target.Zones["catofes."] == previousTargetZone {
		t.Fatal("successful apply retained the old mutable target zone")
	}
	if target.Zones[zone.RootZone].RecordHistory != nil {
		t.Fatalf("unrelated nil record history became non-nil: %#v", target.Zones[zone.RootZone].RecordHistory)
	}
	history := target.Zones["catofes."].RecordHistory["identity"]
	if len(history) != 1 || string(history[0].Value) != "v1" {
		t.Fatalf("record history = %#v, want detached v1", history)
	}

	previousTargetZone.Records["identity"].Value[0] = 'x'
	snapshot.Records["identity"].Value[0] = 'y'
	if got := string(target.Zones["catofes."].Records["identity"].Value); got != "v2" {
		t.Fatalf("installed record changed through retained input: %q", got)
	}
}

func TestApplySnapshotReturnsTargetZoneCOWCandidate(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePrivateKey := testNetwork(t)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	record := signedRecord(t, zonePrivateKey, "catofes.", "identity", []byte("remote"), 1, nil, now.Unix())
	if err := source.PutAt(record, now); err != nil {
		t.Fatalf("PutAt(record): %v", err)
	}
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	target := cloneNetworkState(source)
	delete(target.Zones["catofes."].Records, "identity")
	originalRoot := target.Zones[zone.RootZone]
	originalTarget := target.Zones["catofes."]
	candidate, result, err := ApplySnapshot(target, snapshot, now, DefaultSyncLimits())
	if err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	if result.Records != 1 {
		t.Fatalf("applied records = %d, want 1", result.Records)
	}
	if candidate == target {
		t.Fatal("candidate reused input NetworkState root")
	}
	if candidate.Zones[zone.RootZone] != originalRoot {
		t.Fatal("unmodified root zone was not structurally shared")
	}
	if candidate.Zones["catofes."] == originalTarget {
		t.Fatal("target zone was not detached")
	}
	if target.Zones["catofes."].Records["identity"] != nil {
		t.Fatal("candidate record update leaked into input NetworkState")
	}

	// The complete mutable target zone, including values nested below its
	// maps/slices, must be owned by the candidate.
	candidate.Zones["catofes."].Authority.Keys[0].Key[0] ^= 0xff
	candidate.Zones["catofes."].Records["identity"].Value[0] = 'x'
	if bytes.Equal(candidate.Zones["catofes."].Authority.Keys[0].Key, originalTarget.Authority.Keys[0].Key) {
		t.Fatal("target authority remained shared")
	}
	if target.Zones["catofes."].Records["identity"] != nil {
		t.Fatal("target records map remained shared")
	}
}

func TestApplySnapshotSequentialTargetZoneCOW(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePrivateKey := testNetwork(t)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	v1 := signedRecord(t, zonePrivateKey, "catofes.", "identity", []byte("v1"), 1, nil, now.Unix())
	if err := source.PutAt(v1, now); err != nil {
		t.Fatalf("PutAt(v1): %v", err)
	}
	snapshot1, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot(v1): %v", err)
	}
	v2 := signedRecord(t, zonePrivateKey, "catofes.", "identity", []byte("v2"), 2, photoncrypto.RecordHash(v1), now.Unix()+1)
	if err := source.PutAt(v2, now); err != nil {
		t.Fatalf("PutAt(v2): %v", err)
	}
	snapshot2, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot(v2): %v", err)
	}

	base := emptySnapshotTarget(source)
	first, _, err := ApplySnapshot(base, snapshot1, now, DefaultSyncLimits())
	if err != nil {
		t.Fatalf("ApplySnapshot(v1): %v", err)
	}
	firstTarget := first.Zones["catofes."]
	second, _, err := ApplySnapshot(first, snapshot2, now, DefaultSyncLimits())
	if err != nil {
		t.Fatalf("ApplySnapshot(v2): %v", err)
	}
	if second.Zones[zone.RootZone] != first.Zones[zone.RootZone] {
		t.Fatal("unmodified ancestor was not shared across sequential candidates")
	}
	if second.Zones["catofes."] == firstTarget {
		t.Fatal("second update reused first mutable target zone")
	}
	if got := string(firstTarget.Records["identity"].Value); got != "v1" {
		t.Fatalf("second update leaked into first candidate: %q", got)
	}
	if got := string(second.Zones["catofes."].Records["identity"].Value); got != "v2" {
		t.Fatalf("second candidate record = %q, want v2", got)
	}
}

func TestApplyChildSnapshotUsesParentProof(t *testing.T) {
	now := time.Unix(1000, 0)
	source, _, zonePriv := testNetworkWithKeys(t)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	nodePub, nodePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node): %v", err)
	}
	nodeAuthority := &zone.ZoneAuthority{
		Zone:      "node-b.catofes.",
		Epoch:     1,
		Threshold: photoncrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key: nodePub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}
	delegation := &zone.Delegation{
		ZoneName:  "node-b.catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *nodeAuthority,
	}
	if err := photoncrypto.SignDelegation(delegation, "catofes.", zonePriv); err != nil {
		t.Fatalf("SignDelegation(node-b): %v", err)
	}
	source.Zones["catofes."].Delegations["node-b.catofes."] = delegation
	source.Zones["node-b.catofes."] = zone.NewZoneState("node-b.catofes.", nodeAuthority)
	record := signedRecord(t, nodePriv, "node-b.catofes.", "identity", []byte("node-b"), 1, nil, now.Unix())
	if err := source.PutAt(record, now); err != nil {
		t.Fatalf("PutAt(node-b): %v", err)
	}

	snapshot, err := Snapshot(source, "node-b.catofes.")
	if err != nil {
		t.Fatalf("Snapshot(node-b): %v", err)
	}
	if len(snapshot.ParentProof) == 0 || snapshot.ParentProof[0].ZoneName != "node-b.catofes." {
		t.Fatalf("snapshot parent proof = %#v, want direct node-b delegation", snapshot.ParentProof)
	}

	target := cloneNetworkState(source)
	delete(target.Zones["catofes."].Delegations, zone.ZonePath("node-b.catofes."))
	delete(target.Zones, zone.ZonePath("node-b.catofes."))

	if _, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits()); err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	if err := photoncrypto.VerifyChain(target, "node-b.catofes.", now); err != nil {
		t.Fatalf("VerifyChain(node-b): %v", err)
	}
}

func TestRevocationTombstoneQuarantinesChildZone(t *testing.T) {
	now := time.Unix(1000, 0)
	source, rootPriv, _ := testNetworkWithKeys(t)
	target := cloneNetworkState(source)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)

	delegation := source.Zones[zone.RootZone].Delegations["catofes."]
	revocation := &zone.DelegationRevocation{
		ChildZone:             "catofes.",
		ParentZone:            zone.RootZone,
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		Reason:                "compromised",
		RevokedAt:             now.Unix(),
	}
	if err := photoncrypto.SignDelegationRevocation(revocation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegationRevocation: %v", err)
	}
	source.Zones[zone.RootZone].Revocations["catofes."] = revocation
	delete(source.Zones[zone.RootZone].Delegations, "catofes.")

	snapshot, err := Snapshot(source, zone.RootZone)
	if err != nil {
		t.Fatalf("Snapshot(root): %v", err)
	}
	result, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits())
	if err != nil {
		t.Fatalf("ApplySnapshot(root): %v", err)
	}
	if result.Delegation != 0 {
		t.Fatalf("delegations = %d, want 0", result.Delegation)
	}
	if !target.IsZoneRevoked("catofes.", now) {
		t.Fatalf("catofes. was not marked revoked")
	}
	if err := photoncrypto.VerifyChain(target, "catofes.", now); !errors.Is(err, zone.ErrZoneRevoked) {
		t.Fatalf("VerifyChain = %v, want ErrZoneRevoked", err)
	}
}

func TestApplySnapshotRejectsRecordLimit(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePriv := testNetwork(t)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	if err := source.PutAt(signedRecord(t, zonePriv, "catofes.", "identity", []byte("node-a"), 1, nil, now.Unix()), now); err != nil {
		t.Fatalf("PutAt(identity): %v", err)
	}
	if err := source.PutAt(signedRecord(t, zonePriv, "catofes.", "status", []byte("ready"), 1, nil, now.Unix()), now); err != nil {
		t.Fatalf("PutAt(status): %v", err)
	}
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	target := emptySnapshotTarget(source)
	if _, err := applySnapshotForTest(target, snapshot, now, SyncLimits{MaxRecords: 0, MaxBytes: DefaultSnapshotMaxBytes}); err != nil {
		t.Fatalf("ApplySnapshot without record limit: %v", err)
	}
	target = emptySnapshotTarget(source)
	if _, err := applySnapshotForTest(target, snapshot, now, SyncLimits{MaxRecords: 2, MaxBytes: DefaultSnapshotMaxBytes}); err != nil {
		t.Fatalf("ApplySnapshot at record limit: %v", err)
	}
	target = emptySnapshotTarget(source)
	if _, err := applySnapshotForTest(target, snapshot, now, SyncLimits{MaxRecords: 0, MaxBytes: 1}); !errors.Is(err, ErrZoneSnapshotTooLarge) {
		t.Fatalf("ApplySnapshot byte limit = %v, want ErrZoneSnapshotTooLarge", err)
	}
	target = emptySnapshotTarget(source)
	if _, err := applySnapshotForTest(target, snapshot, now, SyncLimits{MaxRecords: 1, MaxBytes: DefaultSnapshotMaxBytes}); !errors.Is(err, ErrZoneSnapshotTooLarge) {
		t.Fatalf("ApplySnapshot record limit = %v, want ErrZoneSnapshotTooLarge", err)
	}
}

func TestApplySnapshotAcceptsAndRejectsByteBoundary(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePriv := testNetwork(t)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	if err := source.PutAt(signedRecord(t, zonePriv, "catofes.", "identity", []byte("node-a"), 1, nil, now.Unix()), now); err != nil {
		t.Fatalf("PutAt(identity): %v", err)
	}
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	// Use msgpack for size check because it is the default wire codec.
	data, err := msgpack.Marshal(snapshot)
	if err != nil {
		t.Fatalf("Marshal(snapshot): %v", err)
	}

	target := emptySnapshotTarget(source)
	if _, err := applySnapshotForTest(target, snapshot, now, SyncLimits{MaxRecords: 1, MaxBytes: len(data)}); err != nil {
		t.Fatalf("ApplySnapshot at byte limit: %v", err)
	}
	target = emptySnapshotTarget(source)
	if _, err := applySnapshotForTest(target, snapshot, now, SyncLimits{MaxRecords: 1, MaxBytes: len(data) - 1}); !errors.Is(err, ErrZoneSnapshotTooLarge) {
		t.Fatalf("ApplySnapshot below byte limit = %v, want ErrZoneSnapshotTooLarge", err)
	}
}

// applySnapshotForTest preserves the older in-place test setup while the
// production API exposes candidate publication explicitly.
func applySnapshotForTest(ns *zone.NetworkState, snapshot *ZoneSnapshot, now time.Time, limits SyncLimits) (*ApplyResult, error) {
	candidate, result, err := ApplySnapshot(ns, snapshot, now, limits)
	if err != nil {
		return nil, err
	}
	*ns = *candidate
	return result, nil
}

func emptySnapshotTarget(source *zone.NetworkState) *zone.NetworkState {
	target := cloneNetworkState(source)
	target.Zones["catofes."].Records = make(map[string]*zone.Record)
	target.Zones["catofes."].RecordHistory = make(map[string][]*zone.Record)
	return target
}

type capturedNetworkState struct {
	data            []byte
	verifierPointer uintptr
	hasherPointer   uintptr
}

func snapshotAtomicityTarget(source *zone.NetworkState) *zone.NetworkState {
	target := cloneNetworkState(source)
	target.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	target.GlobalRoot = []byte("global-root")
	target.Zones["catofes."].MerkleRoot = []byte("zone-root")
	target.Zones["catofes."].RecordHistory["local"] = []*zone.Record{{
		Zone:    "catofes.",
		Key:     "local",
		Type:    "test",
		Value:   []byte("history"),
		Version: 1,
	}}
	return target
}

func captureNetworkState(t *testing.T, ns *zone.NetworkState) capturedNetworkState {
	t.Helper()
	data, err := json.Marshal(ns)
	if err != nil {
		t.Fatalf("Marshal(network state): %v", err)
	}
	return capturedNetworkState{
		data:            data,
		verifierPointer: reflect.ValueOf(ns.RecordVerifier).Pointer(),
		hasherPointer:   reflect.ValueOf(ns.RecordHasher).Pointer(),
	}
}

func assertNetworkStateUnchanged(t *testing.T, ns *zone.NetworkState, before capturedNetworkState) {
	t.Helper()
	data, err := json.Marshal(ns)
	if err != nil {
		t.Fatalf("Marshal(network state after apply): %v", err)
	}
	if !bytes.Equal(data, before.data) {
		t.Fatalf("network state changed after failed apply:\nbefore: %s\nafter:  %s", before.data, data)
	}
	if got := reflect.ValueOf(ns.RecordVerifier).Pointer(); got != before.verifierPointer {
		t.Fatalf("record verifier changed after failed apply: got %x, want %x", got, before.verifierPointer)
	}
	if got := reflect.ValueOf(ns.RecordHasher).Pointer(); got != before.hasherPointer {
		t.Fatalf("record hasher changed after failed apply: got %x, want %x", got, before.hasherPointer)
	}
}

func testNetwork(t *testing.T) (*zone.NetworkState, ed25519.PrivateKey) {
	t.Helper()
	ns, _, zonePriv := testNetworkWithKeys(t)
	return ns, zonePriv
}

func testNetworkWithKeys(t *testing.T) (*zone.NetworkState, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	zonePub, zonePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(zone): %v", err)
	}
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: photoncrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite},
			}},
		}},
	})
	authority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: photoncrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key: zonePub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite, zone.PermDelegate},
			}},
		}},
	}
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", authority)
	delegation := &zone.Delegation{
		ZoneName:  "catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *authority,
	}
	if err := photoncrypto.SignDelegation(delegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}
	ns.Zones[zone.RootZone].Delegations["catofes."] = delegation
	return ns, rootPriv, zonePriv
}

func signedRecord(t *testing.T, priv ed25519.PrivateKey, path zone.ZonePath, key string, value []byte, version uint64, prev []byte, ts int64) *zone.Record {
	t.Helper()
	record := &zone.Record{
		Zone:      path,
		Key:       key,
		Type:      "node.identity",
		Value:     value,
		Version:   version,
		PrevHash:  prev,
		Timestamp: ts,
	}
	if err := photoncrypto.SignRecord(record, priv); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	return record
}

func TestApplySnapshotRejectsAuthorityRollbackAndSameEpochFork(t *testing.T) {
	now := time.Unix(1000, 0)
	base, _ := testNetwork(t)

	t.Run("same epoch fork", func(t *testing.T) {
		source := cloneNetworkState(base)
		source.Zones[zone.RootZone].Authority.Keys[0].Capabilities[0].Permissions = append(
			source.Zones[zone.RootZone].Authority.Keys[0].Capabilities[0].Permissions,
			zone.PermAllocateIP,
		)
		snapshot, err := Snapshot(source, zone.RootZone)
		if err != nil {
			t.Fatalf("Snapshot: %v", err)
		}
		target := cloneNetworkState(base)
		before := captureNetworkState(t, target)
		if _, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits()); !errors.Is(err, ErrRootAuthorityChange) {
			t.Fatalf("ApplySnapshot = %v, want ErrRootAuthorityChange", err)
		}
		assertNetworkStateUnchanged(t, target, before)
	})

	t.Run("older epoch", func(t *testing.T) {
		source := cloneNetworkState(base)
		snapshot, err := Snapshot(source, zone.RootZone)
		if err != nil {
			t.Fatalf("Snapshot: %v", err)
		}
		target := cloneNetworkState(base)
		target.Zones[zone.RootZone].Authority.Epoch = 2
		before := captureNetworkState(t, target)
		if _, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits()); !errors.Is(err, ErrStaleAuthority) {
			t.Fatalf("ApplySnapshot = %v, want ErrStaleAuthority", err)
		}
		assertNetworkStateUnchanged(t, target, before)
	})
}

func TestApplySnapshotRejectsHigherRootAuthorityWithoutExplicitRecovery(t *testing.T) {
	now := time.Unix(1000, 0)
	source, _ := testNetwork(t)
	source.Zones[zone.RootZone].Authority.Epoch = 2
	source.Zones[zone.RootZone].Authority.Keys[0].Capabilities[0].Permissions = append(
		source.Zones[zone.RootZone].Authority.Keys[0].Capabilities[0].Permissions,
		zone.PermAllocateIP,
	)
	snapshot, err := Snapshot(source, zone.RootZone)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	target, _ := testNetwork(t)
	// Use the same trust lineage while retaining the target's older authority.
	target.Zones[zone.RootZone] = cloneNetworkState(source).Zones[zone.RootZone]
	target.Zones[zone.RootZone].Authority.Epoch = 1
	target.Zones[zone.RootZone].Authority.Keys[0].Capabilities[0].Permissions = []zone.Permission{zone.PermDelegate, zone.PermWrite}

	before := captureNetworkState(t, target)
	if _, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits()); !errors.Is(err, ErrRootAuthorityChange) {
		t.Fatalf("ApplySnapshot = %v, want ErrRootAuthorityChange", err)
	}
	assertNetworkStateUnchanged(t, target, before)
}

func TestApplySnapshotRejectsHigherRootAuthorityWithoutKeyContinuity(t *testing.T) {
	now := time.Unix(1000, 0)
	target, _ := testNetwork(t)
	source := cloneNetworkState(target)
	newPublicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	source.Zones[zone.RootZone].Authority.Epoch = 2
	source.Zones[zone.RootZone].Authority.Keys[0].Key = newPublicKey
	snapshot, err := Snapshot(source, zone.RootZone)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	before := captureNetworkState(t, target)
	if _, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits()); !errors.Is(err, ErrRootAuthorityChange) {
		t.Fatalf("ApplySnapshot = %v, want ErrRootAuthorityChange", err)
	}
	assertNetworkStateUnchanged(t, target, before)
}

func TestApplySnapshotRejectsSameEpochChildAuthorityFork(t *testing.T) {
	now := time.Unix(1000, 0)
	target, rootPrivateKey, _ := testNetworkWithKeys(t)
	source := cloneNetworkState(target)
	forkedAuthority := cloneAuthority(source.Zones["catofes."].Authority)
	forkedAuthority.Keys[0].Capabilities[0].Permissions = append(
		forkedAuthority.Keys[0].Capabilities[0].Permissions,
		zone.PermAllocateIP,
	)
	source.Zones["catofes."].Authority = forkedAuthority
	forkedDelegation := &zone.Delegation{
		ZoneName:  "catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *cloneAuthority(forkedAuthority),
	}
	if err := photoncrypto.SignDelegation(forkedDelegation, zone.RootZone, rootPrivateKey); err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}
	// Model the parent delegation arriving before the child snapshot. The
	// incoming child is trusted by the parent, but must not replace a different
	// local authority at the same epoch.
	target.Zones[zone.RootZone].Delegations["catofes."] = forkedDelegation
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	before := captureNetworkState(t, target)
	if _, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits()); !errors.Is(err, ErrAuthorityConflict) {
		t.Fatalf("ApplySnapshot = %v, want ErrAuthorityConflict", err)
	}
	assertNetworkStateUnchanged(t, target, before)
	store := NewStore(&VerifiedState{ManagedZone: zone.RootZone, Network: target}, nil)
	result, err := store.ImportRecoverySnapshot(context.Background(), RecoveryImport{Snapshot: snapshot}, now)
	if err != nil {
		t.Fatalf("explicit recovery: %v", err)
	}
	if !result.Committed || !bytes.Equal(photoncrypto.AuthorityHash(store.ReadView().State.Network.Zones["catofes."].Authority), photoncrypto.AuthorityHash(forkedAuthority)) {
		t.Fatal("recovery did not install selected child authority")
	}
	assertNetworkStateUnchanged(t, target, before)
}

func TestApplySnapshotRejectsSameEpochDelegationFork(t *testing.T) {
	now := time.Unix(1000, 0)
	target, rootPrivateKey, _ := testNetworkWithKeys(t)
	source := cloneNetworkState(target)
	newPublicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	forkedAuthority := cloneAuthority(source.Zones["catofes."].Authority)
	forkedAuthority.Keys[0].Key = newPublicKey
	forked := &zone.Delegation{
		ZoneName:  "catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *forkedAuthority,
	}
	if err := photoncrypto.SignDelegation(forked, zone.RootZone, rootPrivateKey); err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}
	source.Zones[zone.RootZone].Delegations["catofes."] = forked
	snapshot, err := Snapshot(source, zone.RootZone)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	before := captureNetworkState(t, target)
	if _, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits()); !errors.Is(err, ErrDelegationConflict) {
		t.Fatalf("ApplySnapshot = %v, want ErrDelegationConflict", err)
	}
	assertNetworkStateUnchanged(t, target, before)
}

func TestApplySnapshotRejectsDelegationRollback(t *testing.T) {
	now := time.Unix(1000, 0)
	source, rootPrivateKey, _ := testNetworkWithKeys(t)
	snapshot, err := Snapshot(source, zone.RootZone)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	target := cloneNetworkState(source)
	newer := cloneDelegation(target.Zones[zone.RootZone].Delegations["catofes."])
	newer.Authority.Epoch = 2
	if err := photoncrypto.SignDelegation(newer, zone.RootZone, rootPrivateKey); err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}
	target.Zones[zone.RootZone].Delegations["catofes."] = newer
	before := captureNetworkState(t, target)
	if _, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits()); !errors.Is(err, ErrStaleDelegation) {
		t.Fatalf("ApplySnapshot = %v, want ErrStaleDelegation", err)
	}
	assertNetworkStateUnchanged(t, target, before)
}
