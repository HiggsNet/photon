package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/photonlinux"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	bolt "go.etcd.io/bbolt"
)

func TestLegacyRuntimeStateMigrationIsAtomicAndIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	state, trustedRoot := legacyRuntimeMigrationFixture(t)
	seedLegacyRuntimeState(t, path, state)

	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("bolt.Open: %v", err)
	}
	defer db.Close()
	var report legacyStateMigrationReport
	if err := db.Update(func(tx *bolt.Tx) error {
		var migrated bool
		var err error
		report, migrated, err = migrateLegacyRuntimeStateTx(tx, trustedRoot)
		if err == nil && !migrated {
			t.Fatal("legacy state was not migrated")
		}
		return err
	}); err != nil {
		t.Fatalf("migrateLegacyRuntimeStateTx: %v", err)
	}
	if report.Gossip.PeersMigrated != 1 {
		t.Fatalf("migration report = %+v", report)
	}

	if err := db.View(func(tx *bolt.Tx) error {
		candidate, revision, _, found, err := corestate.LoadBoltState(tx)
		if err != nil {
			return err
		}
		if !found || revision != 0 || candidate.Verified.ManagedZone != zone.RootZone {
			t.Fatalf("common state found/revision/zone = %v/%d/%s", found, revision, candidate.Verified.ManagedZone)
		}
		if !reflect.DeepEqual(candidate.Verified.TrustedRootPublicKey, trustedRoot) || candidate.Gossip.Peers["peer.catofes."].BackoffUntilUnix != 20 {
			t.Fatalf("common state projection = %+v", candidate)
		}
		runtime, found, err := photonlinux.LoadRuntimeStateTx(tx)
		if err != nil {
			return err
		}
		if !found || runtime.PeerCleanups["peer.catofes."].Reason != "expired" {
			t.Fatalf("linux runtime state = %+v", runtime)
		}
		payload, err := json.Marshal(runtime)
		if err != nil {
			return err
		}
		if strings.Contains(string(payload), "identity_key_path") {
			t.Fatalf("legacy identity path survived Linux state migration: %s", payload)
		}
		if meta := tx.Bucket(bucketLegacyMeta); meta != nil && meta.Get([]byte(cliMetaKey)) != nil {
			t.Fatal("legacy cli_state survived migration")
		}
		legacyNetwork, err := zone.LoadNetworkTx(tx)
		if err != nil {
			return err
		}
		if len(legacyNetwork.Zones) != 0 {
			t.Fatalf("legacy zone buckets survived migration: %+v", legacyNetwork.Zones)
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect migrated state: %v", err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		_, migrated, err := migrateLegacyRuntimeStateTx(tx, trustedRoot)
		if err == nil && migrated {
			t.Fatal("second migration reported a change")
		}
		return err
	}); err != nil {
		t.Fatalf("idempotent migration: %v", err)
	}
}

func TestLegacyRuntimeStateMigrationFailureRollsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	state, trustedRoot := legacyRuntimeMigrationFixture(t)
	seedLegacyRuntimeState(t, path, state)
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("bolt.Open: %v", err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketLegacyMeta).Put([]byte(cliMetaKey), []byte("{"))
	}); err != nil {
		t.Fatalf("corrupt legacy fixture: %v", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, _, err := migrateLegacyRuntimeStateTx(tx, trustedRoot)
		return err
	}); err == nil {
		t.Fatal("malformed legacy metadata unexpectedly migrated")
	}
	if err := db.View(func(tx *bolt.Tx) error {
		_, _, _, found, err := corestate.LoadBoltState(tx)
		if err != nil {
			return err
		}
		if found || tx.Bucket([]byte(photonlinux.RuntimeStateBucketName)) != nil {
			t.Fatal("failed migration retained new buckets")
		}
		legacyNetwork, err := zone.LoadNetworkTx(tx)
		if err != nil {
			return err
		}
		if len(legacyNetwork.Zones) == 0 || tx.Bucket(bucketLegacyMeta).Get([]byte(cliMetaKey)) == nil {
			t.Fatal("failed migration removed legacy state")
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect rollback: %v", err)
	}
}

func TestLegacyRuntimeStateMigrationRejectsCoexistingRepresentations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	state, trustedRoot := legacyRuntimeMigrationFixture(t)
	seedLegacyRuntimeState(t, path, state)
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("bolt.Open: %v", err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error {
		_, _, err := migrateLegacyRuntimeStateTx(tx, trustedRoot)
		return err
	}); err != nil {
		t.Fatalf("initial migration: %v", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists(bucketLegacyMeta)
		if err != nil {
			return err
		}
		data, err := json.Marshal(stateMetaFromState(state))
		if err != nil {
			return err
		}
		return meta.Put([]byte(cliMetaKey), data)
	}); err != nil {
		t.Fatalf("create conflicting fixture: %v", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, _, err := migrateLegacyRuntimeStateTx(tx, trustedRoot)
		return err
	}); !errors.Is(err, errLegacyStateConflict) {
		t.Fatalf("coexisting representations error = %v, want errLegacyStateConflict", err)
	}
}

func legacyRuntimeMigrationFixture(t *testing.T) (*stateFile, ed25519.PublicKey) {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	network := zone.NewNetworkState()
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, &zone.ZoneAuthority{
		Zone: zone.RootZone, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: rootPublic}},
	})
	return &stateFile{
		ManagedZone:     zone.RootZone,
		IdentityKeyPath: "/etc/photon/identity.key",
		RootPrivateKey:  rootPrivate,
		Network:         network,
		SyncPeers: map[string]syncPeerState{
			"peer.catofes.": {BackoffUntilUnix: 20, LastError: "diagnostic-only"},
		},
		PeerCleanups: map[string]peerLifecycleCleanupState{
			"peer.catofes.": {CleanupUnix: 30, Reason: "expired"},
		},
	}, rootPublic
}

func seedLegacyRuntimeState(t *testing.T, path string, state *stateFile) {
	t.Helper()
	store, err := zone.OpenBoltStore(path, 0o600)
	if err != nil {
		t.Fatalf("OpenBoltStore: %v", err)
	}
	if err := store.SaveNetworkAndMetaJSON(cliMetaKey, stateMetaFromState(state), state.Network); err != nil {
		_ = store.Close()
		t.Fatalf("seed legacy state: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close legacy store: %v", err)
	}
}
