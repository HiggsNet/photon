package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	bolt "go.etcd.io/bbolt"
)

func TestRestoreStateUpgradesRC6VerifiedLayoutWithoutChangingOwners(t *testing.T) {
	verified, checkpoint, linux, _ := buildTestRoutingOwners(t)
	checkpoint = &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{
		"node-b.catofes.": {LastSyncUnix: 42, BackoffUntilUnix: 100, ObservedEndpoint: "192.0.2.5:33434"},
	}}
	path := filepath.Join(t.TempDir(), "photon.db")
	seedPartitionedStateDB(t, path, verified, checkpoint, linux)
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	var before corestate.VerifiedRevision
	// Turn the fixture into the actual aggregate verified schema used by rc6.
	if err := db.Update(func(tx *bolt.Tx) error {
		candidate, revision, _, _, err := corestate.LoadBoltState(tx)
		if err != nil {
			return err
		}
		before = revision
		payload, err := json.Marshal(map[string]any{
			"managed_zone":            candidate.Verified.ManagedZone,
			"network":                 candidate.Verified.Network,
			"trusted_root_public_key": candidate.Verified.TrustedRootPublicKey,
			"root_private_key":        candidate.Verified.RootPrivateKey,
			"identity_private_key":    candidate.Verified.IdentityPrivateKey,
		})
		if err != nil {
			return err
		}
		common := tx.Bucket([]byte("photon:common-state"))
		bucket := common.Bucket([]byte("verified"))
		if err := bucket.DeleteBucket([]byte("zones")); err != nil {
			return err
		}
		if err := bucket.Put([]byte("payload"), payload); err != nil {
			return err
		}
		var version [8]byte
		binary.BigEndian.PutUint64(version[:], 1)
		return common.Bucket([]byte("meta")).Put([]byte("schema-version"), version[:])
	}); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := corestate.OpenBoltStore(path, 0600, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	owner, found, err := restoreState(store, verified.TrustedRootPublicKey)
	if err != nil || !found {
		store.Close()
		t.Fatalf("restore found=%v err=%v", found, err)
	}
	view := owner.Common.ReadView()
	verifiedJSON, err := json.Marshal(verified)
	if err != nil {
		t.Fatal(err)
	}
	restoredJSON, err := json.Marshal(view.State)
	if err != nil {
		t.Fatal(err)
	}
	if view.Revision != before || !bytes.Equal(restoredJSON, verifiedJSON) || !reflect.DeepEqual(view.Gossip, checkpoint) || !reflect.DeepEqual(owner.ReadLinux(), linux) {
		owner.Close()
		t.Fatalf("layout upgrade changed owners: revision=%v verified=%v checkpoint=%v linux=%v", view.Revision != before, !bytes.Equal(restoredJSON, verifiedJSON), !reflect.DeepEqual(view.Gossip, checkpoint), !reflect.DeepEqual(owner.ReadLinux(), linux))
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	store, err = corestate.OpenBoltStore(path, 0600, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	owner, found, err = restoreState(store, verified.TrustedRootPublicKey)
	if err != nil || !found {
		store.Close()
		t.Fatalf("second restore found=%v err=%v", found, err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(upgraded, again) {
		t.Fatal("second startup rewrote migrated database")
	}
}
