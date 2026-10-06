package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	bolt "go.etcd.io/bbolt"
)

func TestCheckpointNarrowCommitMigrationRollbackAndIsolation(t *testing.T) {
	db := openCommonBoltTestDB(t)
	initial := commonBoltTestCandidate(1)
	initial.Gossip.Peers["untouched"] = PeerCheckpoint{LastSyncUnix: 42}
	commitCommonBoltTestState(t, db, initial, 1)
	disk := &BoltStore{db: db}
	// Simulate v1's monolithic checkpoint, including a stale peer bucket left
	// by a previous upgrade/downgrade. The legacy payload is authoritative.
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketCommonState).Bucket(bucketGossip)
		if err := b.Bucket(bucketCheckpointPeers).Put([]byte("stale"), []byte(`{"failure_count":99}`)); err != nil {
			return err
		}
		payload, _ := json.Marshal(initial.Gossip)
		return b.Put(keyPayload, payload)
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := RestoreStore(initial, 1, disk.CommitCommon, disk.CommitCheckpoints)
	if err != nil {
		t.Fatal(err)
	}
	var verified, untouched []byte
	db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketCommonState)
		verified = append([]byte(nil), c.Bucket(bucketVerified).Get(keyPayload)...)
		untouched = append([]byte(nil), c.Bucket(bucketGossip).Bucket(bucketCheckpointPeers).Get([]byte("untouched"))...)
		return nil
	})
	_, err = store.UpdatePeerCheckpoint(context.Background(), "peer-a", PeerCheckpointPatch{LastSyncUnix: PatchField[int64]{Set: true, Value: 100}})
	if err != nil {
		t.Fatal(err)
	}
	check := func(wantSync int64) {
		t.Helper()
		if err := db.View(func(tx *bolt.Tx) error {
			c := tx.Bucket(bucketCommonState)
			b := c.Bucket(bucketGossip)
			if !bytes.Equal(verified, c.Bucket(bucketVerified).Get(keyPayload)) {
				t.Fatal("verified payload changed")
			}
			if !bytes.Equal(untouched, b.Bucket(bucketCheckpointPeers).Get([]byte("untouched"))) {
				t.Fatal("unrelated peer changed")
			}
			if b.Get(keyPayload) != nil || b.Bucket(bucketCheckpointPeers).Get([]byte("stale")) != nil {
				t.Fatal("legacy payload/stale peer survived migration")
			}
			loaded, rev, report, _, err := LoadBoltState(tx)
			if err != nil {
				return err
			}
			if rev != 1 || report.GossipCheckpointDiscarded || loaded.Gossip.Peers["peer-a"].LastSyncUnix != wantSync || loaded.Gossip.Peers["peer-a"].FailureCount != 2 {
				t.Fatalf("wrong persisted checkpoint/revision: %+v %d", loaded.Gossip, rev)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	check(100)
	// No-op rolls back even the bbolt transaction ID.
	var before int
	db.View(func(tx *bolt.Tx) error { before = tx.ID(); return nil })
	samePeer := store.ReadView().Gossip.Peers["peer-a"]
	if err := disk.CommitCheckpoints(context.Background(), map[string]*PeerCheckpoint{"peer-a": &samePeer}, 1); err != nil {
		t.Fatal(err)
	}
	db.View(func(tx *bolt.Tx) error {
		if tx.ID() != before {
			t.Fatal("no-op committed transaction")
		}
		return nil
	})
	if err := disk.CommitCheckpoints(context.Background(), map[string]*PeerCheckpoint{"peer-a": {LastSyncUnix: 200}}, 2); !errors.Is(err, ErrBoltRevisionInvalid) {
		t.Fatalf("stale revision: %v", err)
	}
	check(100)
	// Callback failure leaves in-memory fields unchanged.
	store.commitCheckpoints = func(context.Context, map[string]*PeerCheckpoint, VerifiedRevision) error {
		return errors.New("disk failed")
	}
	if _, err := store.UpdatePeerCheckpoint(context.Background(), "peer-a", PeerCheckpointPatch{LastSyncUnix: PatchField[int64]{Set: true, Value: 200}}); err == nil {
		t.Fatal("expected write failure")
	}
	if store.ReadView().Gossip.Peers["peer-a"].LastSyncUnix != 100 {
		t.Fatal("published failed checkpoint")
	}
	store.commitCheckpoints = disk.CommitCheckpoints
	if _, err := store.DeletePeerCheckpoints(context.Background(), []string{"peer-a"}); err != nil {
		t.Fatal(err)
	}
	db.View(func(tx *bolt.Tx) error {
		loaded, _, _, _, err := LoadBoltState(tx)
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := loaded.Gossip.Peers["peer-a"]; exists {
			t.Fatal("deleted peer restored")
		}
		return nil
	})
}

func TestRevocationProjectionTracksTimeAndDetachesPeers(t *testing.T) {
	initial := commonBoltTestCandidate(1)
	parent := initial.Verified.Network.Zones[zone.RootZone]
	path := zone.ZonePath("purged.")
	parent.Revocations[path] = &zone.DelegationRevocation{ParentZone: zone.RootZone, ChildZone: path, RevokedAt: 100}
	initial.Gossip.Peers[string(path)] = PeerCheckpoint{LastFailure: &PeerFailure{Message: "original"}}
	store := NewStoreWithCheckpoint(initial.Verified, initial.Gossip, nil, nil)
	before, _ := store.RevokedPeerCheckpoints(time.Unix(99, 0))
	if before[path] {
		t.Fatal("future revocation active early")
	}
	revoked, peers := store.RevokedPeerCheckpoints(time.Unix(100, 0))
	if !revoked[path] || len(peers) != 1 {
		t.Fatalf("missing purged tombstone: %v %v", revoked, peers)
	}
	peers[string(path)].LastFailure.Message = "mutated"
	delete(revoked, path)
	again, values := store.RevokedPeerCheckpoints(time.Unix(101, 0))
	if !again[path] || values[string(path)].LastFailure.Message != "original" {
		t.Fatal("projection aliases store")
	}
}

func TestCheckpointMigrationRollsBackOnWriteFailure(t *testing.T) {
	db := openCommonBoltTestDB(t)
	initial := commonBoltTestCandidate(1)
	commitCommonBoltTestState(t, db, initial, 1)
	payload, err := json.Marshal(initial.Gossip)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketCommonState).Bucket(bucketGossip).Put(keyPayload, payload)
	}); err != nil {
		t.Fatal(err)
	}
	disk := &BoltStore{db: db}
	err = disk.CommitCheckpoints(context.Background(), map[string]*PeerCheckpoint{"a-written-first": {LastSyncUnix: 42}, strings.Repeat("z", bolt.MaxKeySize+1): {LastSyncUnix: 42}}, 1)
	if !errors.Is(err, bolt.ErrKeyTooLarge) {
		t.Fatalf("expected transaction write failure, got %v", err)
	}
	if err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketCommonState).Bucket(bucketGossip)
		if !bytes.Equal(b.Get(keyPayload), payload) {
			t.Fatal("failed migration removed legacy checkpoint")
		}
		if b.Bucket(bucketCheckpointPeers).Get([]byte("a-written-first")) != nil {
			t.Fatal("failed batch partially persisted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPeerCheckpointReadIsNarrowAndDetached(t *testing.T) {
	initial := commonBoltTestCandidate(1)
	initial.Gossip.Peers["unrelated"] = PeerCheckpoint{FailureCount: 99}
	store := NewStoreWithCheckpoint(initial.Verified, initial.Gossip, nil, nil)
	peers := store.PeerCheckpoints([]string{"peer-a", "missing"})
	if len(peers) != 1 {
		t.Fatalf("unexpected peers: %v", peers)
	}
	peers["peer-a"].LastFailure.Message = "mutated"
	if store.PeerCheckpoints([]string{"peer-a"})["peer-a"].LastFailure.Message == "mutated" {
		t.Fatal("read aliases checkpoint")
	}
}
