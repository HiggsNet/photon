package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestStoreImportRecoverySnapshotManagedZoneAndNoop(t *testing.T) {
	now := time.Unix(1000, 0)
	install, _ := identityInstallFixture(t)
	sink := &memoryCommitSink{}
	store := NewStore(&VerifiedState{
		ManagedZone:          install.ManagedZone,
		Network:              install.Network,
		TrustedRootPublicKey: install.TrustedRootPublicKey,
		IdentityPrivateKey:   install.IdentityPrivateKey,
	}, sink.Commit, sink.CommitCheckpoints)

	source := zone.CloneNetworkState(install.Network)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	record := signedRecord(t, install.IdentityPrivateKey, install.ManagedZone, "recovered", []byte("value"), 1, nil, now.Unix())
	if err := source.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}
	snapshot, err := Snapshot(source, install.ManagedZone)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	input := RecoveryImport{Snapshot: snapshot, Limits: SyncLimits{MaxRecords: 16, MaxBytes: 8 << 20}}
	result, err := store.ImportRecoverySnapshot(context.Background(), input, now)
	if err != nil {
		t.Fatalf("ImportRecoverySnapshot: %v", err)
	}
	if !result.Committed || result.Apply == nil || !result.Apply.NetworkChanged || result.Changes.VerifiedRevision != 1 ||
		len(result.Changes.ChangedZones) != 1 || result.Changes.ChangedZones[0] != install.ManagedZone || !result.Changes.SecurityPriority {
		t.Fatalf("result = %+v", result)
	}
	if got := store.ReadView().State.Network.Zones[install.ManagedZone].Records["recovered"]; got == nil || string(got.Value) != "value" {
		t.Fatalf("recovered record = %+v", got)
	}

	noop, err := store.ImportRecoverySnapshot(context.Background(), input, now)
	if err != nil {
		t.Fatalf("ImportRecoverySnapshot(no-op): %v", err)
	}
	if noop.Committed || noop.Apply == nil || noop.Apply.NetworkChanged || noop.Changes.VerifiedRevision != 1 || sink.commits != 1 {
		t.Fatalf("no-op result/commits = %+v/%d", noop, sink.commits)
	}
}

func TestStoreImportRecoverySnapshotKeepsPinnedRoot(t *testing.T) {
	now := time.Unix(1000, 0)
	install, _ := identityInstallFixture(t)
	store := NewStore(&VerifiedState{
		ManagedZone:          install.ManagedZone,
		Network:              install.Network,
		TrustedRootPublicKey: install.TrustedRootPublicKey,
		IdentityPrivateKey:   install.IdentityPrivateKey,
	}, nil, nil)

	otherPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	bad := &ZoneSnapshot{Zone: zone.RootZone, Authority: &zone.ZoneAuthority{
		Zone: zone.RootZone, Epoch: 2, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: otherPublic}},
	}}
	if _, err := store.ImportRecoverySnapshot(context.Background(), RecoveryImport{Snapshot: bad}, now); err == nil {
		t.Fatal("ImportRecoverySnapshot accepted a replacement pinned root")
	}
	view := store.ReadView()
	if view.Revision != 0 || !bytes.Equal(view.State.Network.Zones[zone.RootZone].Authority.Keys[0].Key, install.TrustedRootPublicKey) {
		t.Fatalf("rejected root import changed state: %+v", view)
	}
}

func TestStoreImportRecoverySnapshotRejectsUnpinnedRootReplacement(t *testing.T) {
	now := time.Unix(1000, 0)
	install, _ := identityInstallFixture(t)
	store := NewStore(&VerifiedState{
		ManagedZone:        install.ManagedZone,
		Network:            install.Network,
		IdentityPrivateKey: install.IdentityPrivateKey,
	}, nil, nil)
	otherPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	snapshot := &ZoneSnapshot{Zone: zone.RootZone, Authority: &zone.ZoneAuthority{
		Zone: zone.RootZone, Epoch: 2, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: otherPublic}},
	}}
	if _, err := store.ImportRecoverySnapshot(context.Background(), RecoveryImport{Snapshot: snapshot}, now); !errors.Is(err, ErrRecoveryRootChange) {
		t.Fatalf("root replacement error = %v, want ErrRecoveryRootChange", err)
	}
}

func TestStoreImportRecoverySnapshotPersistenceFailureDoesNotPublish(t *testing.T) {
	now := time.Unix(1000, 0)
	install, _ := identityInstallFixture(t)
	source := zone.CloneNetworkState(install.Network)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	record := signedRecord(t, install.IdentityPrivateKey, install.ManagedZone, "recovered", []byte("value"), 1, nil, now.Unix())
	if err := source.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}
	snapshot, err := Snapshot(source, install.ManagedZone)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	wantErr := errors.New("disk unavailable")
	store := NewStore(&VerifiedState{
		ManagedZone:          install.ManagedZone,
		Network:              install.Network,
		TrustedRootPublicKey: install.TrustedRootPublicKey,
		IdentityPrivateKey:   install.IdentityPrivateKey,
	}, (&memoryCommitSink{err: wantErr}).Commit, (&memoryCommitSink{err: wantErr}).CommitCheckpoints)
	if _, err := store.ImportRecoverySnapshot(context.Background(), RecoveryImport{Snapshot: snapshot}, now); !errors.Is(err, wantErr) {
		t.Fatalf("ImportRecoverySnapshot error = %v, want %v", err, wantErr)
	}
	view := store.ReadView()
	if view.Revision != 0 || view.State.Network.Zones[install.ManagedZone].Records["recovered"] != nil {
		t.Fatalf("persistence failure published recovery state: %+v", view)
	}
}
