package main

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	bolt "go.etcd.io/bbolt"
)

func TestBoltStateStoreLinuxMigratesAndReloadsAggregate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	legacy, trustedRoot := legacyRuntimeMigrationFixture(t)
	seedLegacyRuntimeState(t, path, legacy)

	store, err := corestate.OpenBoltStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatalf("corestate.OpenBoltStore: %v", err)
	}
	snapshot, found, err := loadAndMigrateLinuxState(store, trustedRoot)
	if err != nil {
		t.Fatalf("LoadAndMigrate: %v", err)
	}
	if !found || !snapshot.Migrated || snapshot.Candidate == nil || snapshot.Runtime == nil {
		t.Fatalf("migration snapshot = found=%v %+v", found, snapshot)
	}
	if snapshot.MigrationReport.Gossip.PeersMigrated != 1 {
		t.Fatalf("migration snapshot runtime/report = %+v/%+v", snapshot.Runtime, snapshot.MigrationReport)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := corestate.OpenBoltStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatalf("reopen BoltStore: %v", err)
	}
	defer reopened.Close()
	reloaded, found, err := loadAndMigrateLinuxState(reopened, trustedRoot)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !found || reloaded.Migrated || !reflect.DeepEqual(reloaded.Candidate, snapshot.Candidate) || !reflect.DeepEqual(reloaded.Runtime, snapshot.Runtime) {
		t.Fatalf("reloaded snapshot = found=%v %+v", found, reloaded)
	}
}

func TestBoltStateStoreLinuxRestoresCommonStoreOnOwnedHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	legacy, trustedRoot := legacyRuntimeMigrationFixture(t)
	seedLegacyRuntimeState(t, path, legacy)

	store, err := corestate.OpenBoltStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatalf("corestate.OpenBoltStore: %v", err)
	}
	startup, found, err := loadAndRestoreLinuxState(store, trustedRoot)
	if err != nil {
		t.Fatalf("loadAndRestoreLinuxState: %v", err)
	}
	if !found || !startup.Migrated || startup.Common == nil || startup.Runtime == nil {
		t.Fatalf("startup = found=%v %+v", found, startup)
	}
	before := startup.Common.ReadView()
	result, err := startup.Common.UpdatePeerCheckpoint(context.Background(), "restored.catofes.", corestate.PeerCheckpointPatch{
		BackoffUntilUnix: corestate.PatchField[int64]{Set: true, Value: 42},
	})
	if err != nil {
		t.Fatalf("UpdatePeerCheckpoint: %v", err)
	}
	if !result.Committed || result.Changes.VerifiedRevision != before.Revision {
		t.Fatalf("checkpoint result = %+v, revision before = %d", result, before.Revision)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := corestate.OpenBoltStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatalf("reopen BoltStore: %v", err)
	}
	defer reopened.Close()
	restored, found, err := loadAndRestoreLinuxState(reopened, trustedRoot)
	if err != nil {
		t.Fatalf("restore after checkpoint commit: %v", err)
	}
	if !found || restored.Migrated {
		t.Fatalf("restored = found=%v migrated=%v", found, restored.Migrated)
	}
	after := restored.Common.ReadView()
	if after.Revision != before.Revision || after.Gossip.Peers["restored.catofes."].BackoffUntilUnix != 42 {
		t.Fatalf("restored common view = %+v", after)
	}
	if !reflect.DeepEqual(restored.Runtime, startup.Runtime) {
		t.Fatalf("runtime changed across common commit: before=%+v after=%+v", startup.Runtime, restored.Runtime)
	}
}

func TestPersistedComposedDaemonStateStoreCommitsRuntimeThroughOwnedHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	legacy, trustedRoot := legacyRuntimeMigrationFixture(t)
	seedLegacyRuntimeState(t, path, legacy)

	store, err := corestate.OpenBoltStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatalf("corestate.OpenBoltStore: %v", err)
	}
	startup, found, err := loadAndRestoreLinuxState(store, trustedRoot)
	if err != nil || !found {
		t.Fatalf("loadAndRestoreLinuxState = found %v err %v", found, err)
	}
	composed, err := newPersistedDaemonStateStore(startup.Common, startup.Runtime, store)
	if err != nil {
		t.Fatalf("newPersistedDaemonStateStore: %v", err)
	}
	before := startup.Common.ReadView()
	acls := map[string]endpointACL{"api": {Name: "api"}}
	if _, committed, err := composed.commitEndpointACLsIfRevision(uint64(before.Revision), acls); err != nil || !committed {
		t.Fatalf("commitEndpointACLsIfRevision = committed %v err %v", committed, err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := corestate.OpenBoltStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatalf("reopen BoltStore: %v", err)
	}
	defer reopened.Close()
	restored, found, err := loadAndRestoreLinuxState(reopened, trustedRoot)
	if err != nil || !found {
		t.Fatalf("restore = found %v err %v", found, err)
	}
	if restored.Common.ReadView().Revision != before.Revision {
		t.Fatalf("runtime commit advanced verified revision: before=%d after=%d", before.Revision, restored.Common.ReadView().Revision)
	}
	if restored.Runtime.EndpointACLs["api"].Name != "api" {
		t.Fatalf("restored endpoint ACL runtime = %+v", restored.Runtime.EndpointACLs)
	}
}

func TestBoltStateStoreLinuxCommonCommitUsesOwnedHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	legacy, trustedRoot := legacyRuntimeMigrationFixture(t)
	seedLegacyRuntimeState(t, path, legacy)
	store, err := corestate.OpenBoltStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatalf("corestate.OpenBoltStore: %v", err)
	}
	defer store.Close()
	snapshot, _, err := loadAndMigrateLinuxState(store, trustedRoot)
	if err != nil {
		t.Fatalf("LoadAndMigrate: %v", err)
	}
	if err := store.CommitCommon(context.Background(), snapshot.Candidate, corestate.ChangeSet{VerifiedRevision: snapshot.Revision}); err != nil {
		t.Fatalf("CommitCommon no-op: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.CommitCommon(canceled, snapshot.Candidate, corestate.ChangeSet{VerifiedRevision: snapshot.Revision}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Commit error = %v", err)
	}
}

func TestBoltStateStoreLinuxMetadataOnlyWritesKeepVerifiedRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	legacy, trustedRoot := legacyRuntimeMigrationFixture(t)
	seedLegacyRuntimeState(t, path, legacy)
	store, err := corestate.OpenBoltStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatalf("corestate.OpenBoltStore: %v", err)
	}
	defer store.Close()
	snapshot, _, err := loadAndMigrateLinuxState(store, trustedRoot)
	if err != nil {
		t.Fatalf("LoadAndMigrate: %v", err)
	}

	snapshot.Candidate.Gossip.Peers["metadata.catofes."] = corestate.PeerCheckpoint{BackoffUntilUnix: 42}
	if err := store.CommitCommon(context.Background(), snapshot.Candidate, corestate.ChangeSet{
		VerifiedRevision:        snapshot.Revision,
		GossipCheckpointChanged: true,
	}); err != nil {
		t.Fatalf("checkpoint-only Commit: %v", err)
	}

	runtimeOnly := *snapshot.Runtime
	runtimeOnly.EndpointACLs = map[string]endpointACL{"runtime-only": {Name: "runtime-only"}}
	if err := photonlinux.CommitRuntimeState(store, snapshot.Revision, &runtimeOnly); err != nil {
		t.Fatalf("CommitRuntimeState: %v", err)
	}
	reloaded, found, err := loadAndMigrateLinuxState(store, trustedRoot)
	if err != nil || !found {
		t.Fatalf("reload metadata-only writes = found=%v err=%v", found, err)
	}
	if reloaded.Revision != snapshot.Revision {
		t.Fatalf("metadata-only writes advanced verified revision from %d to %d", snapshot.Revision, reloaded.Revision)
	}
	if reloaded.Runtime.EndpointACLs["runtime-only"].Name != "runtime-only" || reloaded.Candidate.Gossip.Peers["metadata.catofes."].BackoffUntilUnix != 42 {
		t.Fatalf("metadata-only reload = runtime=%+v gossip=%+v", reloaded.Runtime, reloaded.Candidate.Gossip)
	}
	if !reflect.DeepEqual(reloaded.Candidate.Verified, snapshot.Candidate.Verified) {
		t.Fatal("metadata-only writes changed verified payload")
	}
}

func TestBoltStateStoreLinuxRejectsStaleRuntimeCompletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	legacy, trustedRoot := legacyRuntimeMigrationFixture(t)
	seedLegacyRuntimeState(t, path, legacy)
	store, err := corestate.OpenBoltStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatalf("corestate.OpenBoltStore: %v", err)
	}
	defer store.Close()
	snapshot, _, err := loadAndMigrateLinuxState(store, trustedRoot)
	if err != nil {
		t.Fatalf("LoadAndMigrate: %v", err)
	}

	snapshot.Candidate.Verified.Network.GlobalRoot = []byte("newer-network-root")
	if err := store.CommitCommon(context.Background(), snapshot.Candidate, corestate.ChangeSet{
		VerifiedRevision: snapshot.Revision + 1,
		NetworkChanged:   true,
	}); err != nil {
		t.Fatalf("advance verified revision: %v", err)
	}
	stale := *snapshot.Runtime
	stale.EndpointACLs = map[string]endpointACL{"stale": {Name: "stale"}}
	if err := photonlinux.CommitRuntimeState(store, snapshot.Revision, &stale); !errors.Is(err, photonlinux.ErrRuntimeStateSourceRevisionMismatch) {
		t.Fatalf("CommitRuntimeState stale error = %v", err)
	}
	reloaded, _, err := loadAndMigrateLinuxState(store, trustedRoot)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, found := reloaded.Runtime.EndpointACLs["stale"]; found {
		t.Fatal("stale runtime completion was persisted")
	}
}

func TestBoltStateStoreLinuxRejectsNilPlatformState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	legacy, trustedRoot := legacyRuntimeMigrationFixture(t)
	seedLegacyRuntimeState(t, path, legacy)
	store, err := corestate.OpenBoltStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatalf("corestate.OpenBoltStore: %v", err)
	}
	defer store.Close()
	snapshot, _, err := loadAndMigrateLinuxState(store, trustedRoot)
	if err != nil {
		t.Fatalf("LoadAndMigrate: %v", err)
	}
	if err := photonlinux.CommitRuntimeState(store, snapshot.Revision, nil); err == nil {
		t.Fatal("nil Linux runtime state unexpectedly committed")
	}
}

func TestBoltStateStoreLinuxRejectsExternalHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	store, err := corestate.OpenBoltStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatalf("corestate.OpenBoltStore: %v", err)
	}
	defer store.Close()
	started := time.Now()
	_, err = corestate.OpenBoltStore(path, 0o600, 25*time.Millisecond)
	if !errors.Is(err, bolt.ErrTimeout) {
		t.Fatalf("second open error = %v, want bbolt timeout", err)
	}
	if time.Since(started) > time.Second {
		t.Fatalf("external lock conflict did not respect timeout")
	}
}
