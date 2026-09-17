package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestStoreInstallIdentityInitialNoopAndDetached(t *testing.T) {
	now := time.Unix(1000, 0)
	install, _ := identityInstallFixture(t)
	sink := &memoryCommitSink{}
	store := NewStore(nil, sink.Commit)

	result, err := store.InstallIdentity(context.Background(), install, now)
	if err != nil {
		t.Fatalf("InstallIdentity(initial): %v", err)
	}
	wantZones := []zone.ZonePath{zone.RootZone, "catofes.", "node-a.catofes."}
	if !result.Committed || result.Changes.VerifiedRevision != 1 || !result.Changes.SecurityPriority ||
		!result.Changes.NetworkChanged || !slices.Equal(result.Changes.ChangedZones, wantZones) {
		t.Fatalf("initial result = %+v, want revision 1 and zones %v", result, wantZones)
	}
	if sink.commits != 1 {
		t.Fatalf("commits = %d, want 1", sink.commits)
	}

	noop, err := store.InstallIdentity(context.Background(), install, now)
	if err != nil {
		t.Fatalf("InstallIdentity(no-op): %v", err)
	}
	if noop.Committed || noop.Changes.VerifiedRevision != 1 || sink.commits != 1 {
		t.Fatalf("no-op result/commits = %+v/%d", noop, sink.commits)
	}

	install.IdentityPrivateKey[0] ^= 0xff
	install.TrustedRootPublicKey[0] ^= 0xff
	install.Network.Zones["node-a.catofes."].Authority.Epoch = 99
	view := store.ReadView()
	if view.Revision != 1 || view.State.Network.Zones["node-a.catofes."].Authority.Epoch != 1 ||
		bytes.Equal(view.State.TrustedRootPublicKey, install.TrustedRootPublicKey) {
		t.Fatalf("installed state retained input pointers: %+v", view)
	}
}

func TestStoreInstallIdentityRefreshPreservesLocalContentAndRejectsDowngrade(t *testing.T) {
	now := time.Unix(1000, 0)
	initial, parentPrivate := identityInstallFixture(t)
	record := signedRecord(t, initial.IdentityPrivateKey, initial.ManagedZone, "local-note", []byte("keep"), 1, nil, now.Unix())
	initial.Network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	if err := initial.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt(local-note): %v", err)
	}
	store := NewStore(nil, nil)
	if _, err := store.InstallIdentity(context.Background(), initial, now); err != nil {
		t.Fatalf("InstallIdentity(initial): %v", err)
	}

	refresh := cloneIdentityInstall(initial)
	managed := refresh.ManagedZone
	nextAuthority := cloneAuthority(refresh.Network.Zones[managed].Authority)
	nextAuthority.Epoch++
	nextAuthority.Keys[0].Capabilities[0].Permissions = append(
		nextAuthority.Keys[0].Capabilities[0].Permissions,
		zone.PermAllocateIP,
	)
	delegation := &zone.Delegation{ZoneName: managed, Scope: zone.DelegationScopeDirectChild, Authority: *cloneAuthority(nextAuthority)}
	if err := photoncrypto.SignDelegation(delegation, managed.Parent(), parentPrivate); err != nil {
		t.Fatalf("SignDelegation(refresh): %v", err)
	}
	refresh.Network.Zones[managed.Parent()].Delegations[managed] = delegation
	refresh.Network.Zones[managed].Authority = cloneAuthority(nextAuthority)
	refresh.Network.Zones[managed].ParentProof = []*zone.Delegation{cloneDelegation(delegation)}
	delete(refresh.Network.Zones[managed].Records, "local-note")

	result, err := store.InstallIdentity(context.Background(), refresh, now.Add(time.Second))
	if err != nil {
		t.Fatalf("InstallIdentity(refresh): %v", err)
	}
	if !result.Committed || result.Changes.VerifiedRevision != 2 || !slices.Equal(
		result.Changes.ChangedZones,
		[]zone.ZonePath{"catofes.", "node-a.catofes."},
	) {
		t.Fatalf("refresh result = %+v", result)
	}
	view := store.ReadView()
	managedState := view.State.Network.Zones[managed]
	if managedState.Authority.Epoch != 2 || managedState.Records["local-note"] == nil {
		t.Fatalf("refreshed managed state = %+v, want epoch 2 with local record", managedState)
	}

	if _, err := store.InstallIdentity(context.Background(), initial, now.Add(2*time.Second)); !errors.Is(err, ErrAuthorityEpochStale) {
		t.Fatalf("downgrade error = %v, want ErrAuthorityEpochStale", err)
	}
	conflict := cloneIdentityInstall(refresh)
	conflictAuthority := cloneAuthority(conflict.Network.Zones[managed].Authority)
	conflictAuthority.Keys[0].Capabilities[0].Permissions = []zone.Permission{zone.PermWrite}
	conflictDelegation := &zone.Delegation{ZoneName: managed, Scope: zone.DelegationScopeDirectChild, Authority: *cloneAuthority(conflictAuthority)}
	if err := photoncrypto.SignDelegation(conflictDelegation, managed.Parent(), parentPrivate); err != nil {
		t.Fatalf("SignDelegation(conflict): %v", err)
	}
	conflict.Network.Zones[managed.Parent()].Delegations[managed] = conflictDelegation
	conflict.Network.Zones[managed].Authority = conflictAuthority
	conflict.Network.Zones[managed].ParentProof = []*zone.Delegation{cloneDelegation(conflictDelegation)}
	if _, err := store.InstallIdentity(context.Background(), conflict, now.Add(2*time.Second)); !errors.Is(err, ErrAuthorityEpochConflict) {
		t.Fatalf("same-epoch conflict error = %v, want ErrAuthorityEpochConflict", err)
	}
	if got := store.ReadView(); got.Revision != 2 || got.State.Network.Zones[managed].Authority.Epoch != 2 {
		t.Fatalf("downgrade changed state: revision=%d authority=%+v", got.Revision, got.State.Network.Zones[managed].Authority)
	}
}

func TestStoreInstallIdentityRejectsIdentityAndTrustChanges(t *testing.T) {
	now := time.Unix(1000, 0)
	install, _ := identityInstallFixture(t)
	store := NewStore(nil, nil)
	if _, err := store.InstallIdentity(context.Background(), install, now); err != nil {
		t.Fatalf("InstallIdentity(initial): %v", err)
	}

	changedZone := cloneIdentityInstall(install)
	changedZone.ManagedZone = "catofes."
	if _, err := store.InstallIdentity(context.Background(), changedZone, now); !errors.Is(err, ErrManagedZoneChange) {
		t.Fatalf("managed zone change error = %v, want ErrManagedZoneChange", err)
	}
	changedRoot := cloneIdentityInstall(install)
	otherRoot, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(other root): %v", err)
	}
	changedRoot.TrustedRootPublicKey = otherRoot
	if _, err := store.InstallIdentity(context.Background(), changedRoot, now); !errors.Is(err, ErrTrustedRootChange) {
		t.Fatalf("trusted root change error = %v, want ErrTrustedRootChange", err)
	}
	if got := store.ReadView(); got.Revision != 1 {
		t.Fatalf("rejected identity change advanced revision to %d", got.Revision)
	}
}

func TestStoreInstallIdentityPersistenceFailureDoesNotPublish(t *testing.T) {
	install, _ := identityInstallFixture(t)
	wantErr := errors.New("disk unavailable")
	sink := &memoryCommitSink{err: wantErr}
	store := NewStore(nil, sink.Commit)

	if _, err := store.InstallIdentity(context.Background(), install, time.Unix(1000, 0)); !errors.Is(err, wantErr) {
		t.Fatalf("InstallIdentity error = %v, want %v", err, wantErr)
	}
	view := store.ReadView()
	if view.Revision != 0 || verifiedStateInitialized(view.State) || sink.commits != 0 {
		t.Fatalf("persistence failure published state: view=%+v commits=%d", view, sink.commits)
	}
}

func TestStoreInstallIdentityRejectsUnauthorizedPrivateKey(t *testing.T) {
	install, _ := identityInstallFixture(t)
	_, otherPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(other identity): %v", err)
	}
	install.IdentityPrivateKey = otherPrivate
	store := NewStore(nil, nil)
	if _, err := store.InstallIdentity(context.Background(), install, time.Unix(1000, 0)); err == nil {
		t.Fatal("InstallIdentity accepted a private key absent from the managed authority")
	}
	if verifiedStateInitialized(store.ReadView().State) {
		t.Fatal("unauthorized identity was published")
	}
}

func identityInstallFixture(t *testing.T) (IdentityInstall, ed25519.PrivateKey) {
	t.Helper()
	network, _, identityPrivate, parentPrivate := managedAuthorityFixture(t, true)
	root := network.Zones[zone.RootZone]
	if root == nil || root.Authority == nil || len(root.Authority.Keys) == 0 {
		t.Fatal("fixture root authority is missing")
	}
	root.Authority = photoncrypto.ConfiguredRootAuthority(root.Authority.Keys[0].Key)
	return IdentityInstall{
		ManagedZone:          "node-a.catofes.",
		Network:              network,
		TrustedRootPublicKey: append(ed25519.PublicKey(nil), root.Authority.Keys[0].Key...),
		IdentityPrivateKey:   append(ed25519.PrivateKey(nil), identityPrivate...),
	}, parentPrivate
}

func cloneIdentityInstall(value IdentityInstall) IdentityInstall {
	value.Network = zone.CloneNetworkState(value.Network)
	value.TrustedRootPublicKey = append(ed25519.PublicKey(nil), value.TrustedRootPublicKey...)
	value.IdentityPrivateKey = append(ed25519.PrivateKey(nil), value.IdentityPrivateKey...)
	return value
}
