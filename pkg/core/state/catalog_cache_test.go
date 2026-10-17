package state

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestCatalogCacheRechecksRevocationTime(t *testing.T) {
	network := zone.NewNetworkState()
	for _, path := range []zone.ZonePath{zone.RootZone, "parent.", "child.parent."} {
		network.Zones[path] = zone.NewZoneState(path, &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1})
	}
	network.Zones[zone.RootZone].Revocations["parent."] = &zone.DelegationRevocation{
		ParentZone: zone.RootZone, ChildZone: "parent.", RevokedAt: 100,
	}
	store := NewStore(&VerifiedState{Network: network}, nil, nil)
	// The clock can cross the revocation boundary in either direction without
	// a verified commit. Descendants must follow the parent in both directions.
	for _, tc := range []struct {
		unix  int64
		count int
	}{{99, 3}, {100, 1}, {101, 1}, {99, 3}} {
		store.mu.RLock()
		got := store.zoneDigestsLocked(time.Unix(tc.unix, 0))
		store.mu.RUnlock()
		if len(got) != tc.count || store.VerifiedRevision() != 0 {
			t.Fatalf("at %d: got %d zones at revision %d, want %d/0", tc.unix, len(got), store.VerifiedRevision(), tc.count)
		}
		// Mutating both the slice and a hash must never alter the cached roots.
		got[0].RootHash[0] ^= 0xff
		got[0].Zone = "changed."
	}
	if got := store.ReadCatalog().Digests; !reflect.DeepEqual(got, ZoneDigests(network)) {
		t.Fatal("catalog was changed by a caller or failed to apply current time")
	}
}

func TestCatalogCachePublishesOnlyAfterPersistence(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("fail=%v", fail), func(t *testing.T) {
			network, _, identity, _ := managedAuthorityFixture(t, true)
			entered, release := make(chan struct{}), make(chan struct{})
			wantErr := errors.New("disk write failed")
			store := NewStore(&VerifiedState{ManagedZone: "node-a.catofes.", Network: network, IdentityPrivateKey: identity},
				func(context.Context, *CommitCandidate, ChangeSet) error {
					close(entered)
					<-release
					if fail {
						return wantErr
					}
					return nil
				}, func(context.Context, map[string]*PeerCheckpoint, VerifiedRevision) error { return nil })
			before := store.ReadCatalog()
			done := make(chan error, 1)
			go func() {
				_, err := store.ApplyLocalIntent(context.Background(), PutRecordIntent{
					Zone: "node-a.catofes.", Key: "catalog-test", Type: "text", Value: []byte("changed"),
				}, time.Unix(1000, 0))
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				close(release)
				t.Fatal("commit did not reach persistence")
			}
			pending := store.ReadCatalog()
			close(release)
			if err := <-done; (fail && !errors.Is(err, wantErr)) || (!fail && err != nil) {
				t.Fatalf("commit error = %v", err)
			}
			if !reflect.DeepEqual(before, pending) {
				t.Fatal("uncommitted catalog became visible")
			}
			after := store.ReadCatalog()
			if fail != reflect.DeepEqual(before, after) {
				t.Fatal("catalog did not follow commit outcome")
			}
			if !reflect.DeepEqual(after.Digests, ZoneDigests(store.ReadView().State.Network)) {
				t.Fatal("cached catalog differs from committed state")
			}
			if _, err := store.UpdatePeerCheckpoint(context.Background(), "peer", PeerCheckpointPatch{
				LastSyncUnix: PatchField[int64]{Set: true, Value: 123},
			}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(after, store.ReadCatalog()) {
				t.Fatal("checkpoint-only update changed catalog")
			}
		})
	}
}

func TestCatalogCacheConcurrentReadersAndCommits(t *testing.T) {
	network, _, identity, _ := managedAuthorityFixture(t, true)
	store := NewStore(&VerifiedState{ManagedZone: "node-a.catofes.", Network: network, IdentityPrivateKey: identity}, nil, nil)
	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			for range 30 {
				store.mu.RLock()
				got := store.zoneDigestsLocked(time.Now())
				want := ZoneDigests(store.state.Network)
				store.mu.RUnlock()
				if !reflect.DeepEqual(got, want) {
					t.Error("catalog did not match pinned state")
				}
			}
		})
	}
	for i := range 10 {
		if _, err := store.ApplyLocalIntent(context.Background(), PutRecordIntent{
			Zone: "node-a.catofes.", Key: "catalog-test", Type: "text", Value: []byte(fmt.Sprint(i)),
		}, time.Unix(1000+int64(i), 0)); err != nil {
			t.Fatal(err)
		}
	}
	readers.Wait()
}

func TestCatalogCacheIdentityRemoteAndRecoveryPublications(t *testing.T) {
	now := time.Unix(1000, 0)
	limits := SyncLimits{MaxZones: 16, MaxRecords: 64, MaxBytes: 8 << 20}
	install, parentPrivate := identityInstallFixture(t)
	store := NewStore(nil, nil, nil)
	check := func() {
		t.Helper()
		view := store.ReadView()
		got, revision := store.ZoneDigests()
		if revision != view.Revision || !reflect.DeepEqual(got, ZoneDigests(view.State.Network)) ||
			!reflect.DeepEqual(got, store.ReadCatalog().Digests) {
			t.Fatal("catalog does not match published state")
		}
	}
	check() // Populate the empty revision-zero snapshot before identity install.
	if _, err := store.InstallIdentity(context.Background(), install, now); err != nil {
		t.Fatal(err)
	}
	check()
	for _, path := range []zone.ZonePath{"catofes.", install.ManagedZone} {
		source := store.ReadView().State.Network
		source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
		private := parentPrivate
		if path == install.ManagedZone {
			private = install.IdentityPrivateKey
		}
		record := signedRecord(t, private, path, "catalog-change", []byte("new"), 1, nil, now.Unix())
		if err := source.PutAt(record, now); err != nil {
			t.Fatal(err)
		}
		snapshot, err := Snapshot(source, path)
		if err != nil {
			t.Fatal(err)
		}
		if path == install.ManagedZone {
			_, err = store.ImportRecoverySnapshot(context.Background(), RecoveryImport{Snapshot: snapshot, Limits: limits}, now)
		} else {
			result, applyErr := store.ApplyRemoteBatch(context.Background(), "peer", []RemoteSnapshot{{Snapshot: snapshot, Limits: limits}}, now)
			err = applyErr
			if len(result.Outcomes) != 1 || result.Outcomes[0].Err != nil {
				t.Fatalf("remote result = %+v", result)
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		check()
	}
}

func TestCatalogCacheDropsPurgedZonesEvenIfClockMovesBack(t *testing.T) {
	install, _ := identityInstallFixture(t)
	network := install.Network
	path := zone.ZonePath("removed.catofes.")
	network.Zones[path] = zone.NewZoneState(path, nil)
	network.Zones["catofes."].Revocations[path] = &zone.DelegationRevocation{
		ParentZone: "catofes.", ChildZone: path, RevokedAt: 100,
	}
	store := NewStore(&VerifiedState{ManagedZone: install.ManagedZone, Network: network,
		TrustedRootPublicKey: install.TrustedRootPublicKey, IdentityPrivateKey: install.IdentityPrivateKey}, nil, nil)
	store.ReadCatalog() // The raw cache includes even currently hidden zones.
	result, err := store.PurgeRevoked(context.Background(), time.Unix(1000, 0), path)
	if err != nil || !result.Changes.NetworkChanged {
		t.Fatalf("purge = %+v, %v", result, err)
	}
	store.mu.RLock()
	got := store.zoneDigestsLocked(time.Unix(99, 0))
	store.mu.RUnlock()
	for _, digest := range got {
		if digest.Zone == path {
			t.Fatal("clock rollback resurrected a purged zone")
		}
	}
}
