package state

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"path/filepath"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
	bolt "go.etcd.io/bbolt"
)

var errNoCommonBoltChanges = errors.New("no common bbolt changes")

func TestBoltStateRoundTripRevisionAndNoop(t *testing.T) {
	db := openCommonBoltTestDB(t)
	candidate := commonBoltTestCandidate(1)
	next := VerifiedRevision(1)
	commitCommonBoltTestState(t, db, candidate, next)

	var loaded *CommitCandidate
	var revision VerifiedRevision
	if err := db.View(func(tx *bolt.Tx) error {
		var report BoltLoadReport
		var found bool
		var err error
		loaded, revision, report, found, err = LoadBoltState(tx)
		if err != nil {
			return err
		}
		if !found || report.GossipCheckpointDiscarded {
			t.Fatalf("found/report = %v/%+v, want true/clean", found, report)
		}
		return nil
	}); err != nil {
		t.Fatalf("LoadBoltState: %v", err)
	}
	if revision != next {
		t.Fatalf("revision = %d, want %d", revision, next)
	}
	if got := loaded.Verified.Network.Zones["node-a.catofes."].Authority.Epoch; got != 1 {
		t.Fatalf("managed authority epoch = %d, want 1", got)
	}
	if got := loaded.Gossip.Peers["peer-a"].FailureCount; got != 2 {
		t.Fatalf("peer failure count = %d, want 2", got)
	}

	// Returned state is detached from both the input and future loads.
	loaded.Verified.Network.Zones["node-a.catofes."].Authority.Epoch = 99
	loaded.Gossip.Peers["peer-a"] = PeerCheckpoint{FailureCount: 99}
	if err := db.View(func(tx *bolt.Tx) error {
		again, _, _, _, err := LoadBoltState(tx)
		if err != nil {
			return err
		}
		if got := again.Verified.Network.Zones["node-a.catofes."].Authority.Epoch; got != 1 {
			t.Fatalf("retained mutation changed persisted epoch to %d", got)
		}
		if got := again.Gossip.Peers["peer-a"].FailureCount; got != 2 {
			t.Fatalf("retained mutation changed persisted checkpoint to %d", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("reload detached state: %v", err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		changed, err := CommitBoltState(tx, candidate, ChangeSet{VerifiedRevision: next})
		if err != nil {
			return err
		}
		if changed {
			t.Fatal("byte-identical common commit reported a change")
		}
		return errNoCommonBoltChanges
	}); !errors.Is(err, errNoCommonBoltChanges) {
		t.Fatalf("no-op transaction error = %v", err)
	}

	changedWithoutRevision := commonBoltTestCandidate(2)
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := CommitBoltState(tx, changedWithoutRevision, ChangeSet{VerifiedRevision: next})
		return err
	}); !errors.Is(err, ErrBoltRevisionInvalid) {
		t.Fatalf("payload/revision mismatch error = %v, want ErrBoltRevisionInvalid", err)
	}
}

func TestBoltStateCheckpointChangeDoesNotAdvanceVerifiedRevision(t *testing.T) {
	db := openCommonBoltTestDB(t)
	candidate := commonBoltTestCandidate(1)
	commitCommonBoltTestState(t, db, candidate, 1)
	candidate.Gossip.Peers["peer-a"] = PeerCheckpoint{FailureCount: 3}

	if err := db.Update(func(tx *bolt.Tx) error {
		changed, err := CommitBoltState(tx, candidate, ChangeSet{
			VerifiedRevision:        1,
			GossipCheckpointChanged: true,
		})
		if err != nil {
			return err
		}
		if !changed {
			t.Fatal("checkpoint update reported no change")
		}
		return nil
	}); err != nil {
		t.Fatalf("commit checkpoint: %v", err)
	}
	if err := db.View(func(tx *bolt.Tx) error {
		loaded, revision, _, _, err := LoadBoltState(tx)
		if err != nil {
			return err
		}
		if revision != 1 || loaded.Gossip.Peers["peer-a"].FailureCount != 3 {
			t.Fatalf("revision/checkpoint = %d/%+v", revision, loaded.Gossip.Peers["peer-a"])
		}
		return nil
	}); err != nil {
		t.Fatalf("load checkpoint: %v", err)
	}
}

func TestBoltStateRejectsTrustedRootPinChange(t *testing.T) {
	db := openCommonBoltTestDB(t)
	firstPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(first): %v", err)
	}
	secondPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(second): %v", err)
	}
	candidate := commonBoltTestCandidate(1)
	candidate.Verified.TrustedRootPublicKey = firstPublic
	candidate.Verified.Network.Zones[zone.RootZone].Authority.Keys = []zone.AuthorizedKey{{Key: firstPublic}}
	commitCommonBoltTestState(t, db, candidate, 1)

	replacement := cloneCommitCandidate(candidate.Verified, candidate.Gossip)
	replacement.Verified.TrustedRootPublicKey = secondPublic
	replacement.Verified.Network.Zones[zone.RootZone].Authority.Keys = []zone.AuthorizedKey{{Key: secondPublic}}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := CommitBoltState(tx, replacement, ChangeSet{VerifiedRevision: 2})
		return err
	}); !errors.Is(err, ErrTrustedRootPinChange) {
		t.Fatalf("pin replacement error = %v, want ErrTrustedRootPinChange", err)
	}
}

func TestBoltStateComposesAtomicallyWithPlatformBucket(t *testing.T) {
	db := openCommonBoltTestDB(t)
	initial := commonBoltTestCandidate(1)
	commitCommonBoltTestState(t, db, initial, 1)

	invalid := commonBoltTestCandidate(2)
	invalid.Verified.ManagedZone = "missing.catofes."
	err := db.Update(func(tx *bolt.Tx) error {
		platform, createErr := tx.CreateBucketIfNotExists([]byte("linux-runtime"))
		if createErr != nil {
			return createErr
		}
		if putErr := platform.Put([]byte("status"), []byte("new")); putErr != nil {
			return putErr
		}
		_, commitErr := CommitBoltState(tx, invalid, ChangeSet{VerifiedRevision: 2})
		return commitErr
	})
	if !errors.Is(err, ErrInvalidStateRoot) {
		t.Fatalf("invalid composed commit error = %v, want ErrInvalidStateRoot", err)
	}

	if err := db.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte("linux-runtime")) != nil {
			t.Fatal("failed common commit retained platform bucket")
		}
		loaded, revision, _, found, loadErr := LoadBoltState(tx)
		if loadErr != nil {
			return loadErr
		}
		if !found || revision != 1 {
			t.Fatalf("found/revision = %v/%d", found, revision)
		}
		if got := loaded.Verified.Network.Zones["node-a.catofes."].Authority.Epoch; got != 1 {
			t.Fatalf("failed transaction persisted epoch %d, want 1", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect rollback: %v", err)
	}
}

func TestBoltStateDiscardsOnlyCorruptGossipCheckpoint(t *testing.T) {
	db := openCommonBoltTestDB(t)
	commitCommonBoltTestState(t, db, commonBoltTestCandidate(1), 1)
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketCommonState).Bucket(bucketGossip).Put(keyPayload, []byte("{"))
	}); err != nil {
		t.Fatalf("corrupt checkpoint fixture: %v", err)
	}

	if err := db.View(func(tx *bolt.Tx) error {
		loaded, revision, report, found, err := LoadBoltState(tx)
		if err != nil {
			return err
		}
		if !found || !report.GossipCheckpointDiscarded {
			t.Fatalf("found/report = %v/%+v, want recoverable discard", found, report)
		}
		if revision != 1 {
			t.Fatalf("verified revision = %d", revision)
		}
		if len(loaded.Gossip.Peers) != 0 {
			t.Fatalf("discarded checkpoint peers = %#v, want empty", loaded.Gossip.Peers)
		}
		return nil
	}); err != nil {
		t.Fatalf("LoadBoltState: %v", err)
	}
}

func TestBoltStateFailsClosedOnUnsupportedSchema(t *testing.T) {
	db := openCommonBoltTestDB(t)
	commitCommonBoltTestState(t, db, commonBoltTestCandidate(1), 1)
	if err := db.Update(func(tx *bolt.Tx) error {
		return putUint64Raw(tx.Bucket(bucketCommonState).Bucket(bucketCommonMeta), keySchemaVersion, BoltSchemaVersion+1)
	}); err != nil {
		t.Fatalf("write future schema fixture: %v", err)
	}
	if err := db.View(func(tx *bolt.Tx) error {
		_, _, _, _, err := LoadBoltState(tx)
		return err
	}); !errors.Is(err, ErrBoltSchemaUnsupported) {
		t.Fatalf("future schema error = %v, want ErrBoltSchemaUnsupported", err)
	}
}

func openCommonBoltTestDB(t *testing.T) *bolt.DB {
	t.Helper()
	db, err := bolt.Open(filepath.Join(t.TempDir(), "state.db"), 0o600, nil)
	if err != nil {
		t.Fatalf("bolt.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("bolt.Close: %v", err)
		}
	})
	return db
}

func commonBoltTestCandidate(epoch uint64) *CommitCandidate {
	network := zone.NewNetworkState()
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, &zone.ZoneAuthority{Zone: zone.RootZone, Epoch: 1, Threshold: 1})
	network.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", &zone.ZoneAuthority{Zone: "node-a.catofes.", Epoch: epoch, Threshold: 1})
	return &CommitCandidate{
		Verified: &VerifiedState{ManagedZone: "node-a.catofes.", Network: network},
		Gossip: &GossipCheckpoint{Peers: map[string]PeerCheckpoint{
			"peer-a": {
				FailureCount: 2, DiscoveredEndpoint: "192.0.2.1:443",
				LastFailure: &PeerFailure{Code: "transport", Message: "connection refused", AtUnix: 42},
			},
		}},
	}
}

func commitCommonBoltTestState(t *testing.T, db *bolt.DB, candidate *CommitCandidate, next VerifiedRevision) {
	t.Helper()
	if err := db.Update(func(tx *bolt.Tx) error {
		changed, err := CommitBoltState(tx, candidate, ChangeSet{VerifiedRevision: next})
		if err != nil {
			return err
		}
		if !changed {
			t.Fatal("common state seed unexpectedly reported no change")
		}
		return nil
	}); err != nil {
		t.Fatalf("CommitBoltState: %v", err)
	}
}

func putUint64Raw(bucket *bolt.Bucket, key []byte, value uint64) error {
	var data [8]byte
	data[0] = byte(value >> 56)
	data[1] = byte(value >> 48)
	data[2] = byte(value >> 40)
	data[3] = byte(value >> 32)
	data[4] = byte(value >> 24)
	data[5] = byte(value >> 16)
	data[6] = byte(value >> 8)
	data[7] = byte(value)
	return bucket.Put(key, data[:])
}

func TestLoadBoltStateRepairsOnlyLegacyRootCapabilities(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, extraKey := range []bool{false, true} {
		t.Run(fmt.Sprintf("extra_key_%t", extraKey), func(t *testing.T) {
			db := openCommonBoltTestDB(t)
			candidate := commonBoltTestCandidate(1)
			candidate.Verified.TrustedRootPublicKey = pub
			candidate.Verified.Network.Zones[zone.RootZone].Authority = photoncrypto.ConfiguredRootAuthority(pub)
			commitCommonBoltTestState(t, db, candidate, 1)
			if err := db.Update(func(tx *bolt.Tx) error {
				bucket := tx.Bucket(bucketCommonState).Bucket(bucketVerified)
				var persisted persistedVerifiedState
				if err := json.Unmarshal(bucket.Get(keyPayload), &persisted); err != nil {
					return err
				}
				a := persisted.Network.Zones[zone.RootZone].Authority
				a.Keys[0].Capabilities = []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite}}}
				if extraKey {
					a.Keys = append(a.Keys, a.Keys[0])
				}
				data, err := json.Marshal(persisted)
				if err != nil {
					return err
				}
				return bucket.Put(keyPayload, data)
			}); err != nil {
				t.Fatal(err)
			}
			if err := db.View(func(tx *bolt.Tx) error {
				loaded, revision, _, found, err := LoadBoltState(tx)
				if extraKey {
					if !errors.Is(err, ErrBoltStateCorrupt) {
						t.Fatalf("extra root key error = %v", err)
					}
					return nil
				}
				if err != nil {
					return err
				}
				if !found || revision != 1 {
					t.Fatalf("found/revision = %v/%d", found, revision)
				}
				if err := photoncrypto.VerifyPinnedRoot(loaded.Verified.Network, pub); err != nil {
					return err
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if !extraKey {
				store := &BoltStore{db: db}
				loaded, revision, report, found, err := store.LoadCommon()
				if err != nil || !found || !report.RootAuthorityRepaired || revision != 2 {
					t.Fatalf("startup repair: revision=%d report=%+v err=%v", revision, report, err)
				}
				loaded.Gossip.Peers["peer-a"] = PeerCheckpoint{FailureCount: 3}
				if err := store.CommitCommon(context.Background(), loaded, ChangeSet{VerifiedRevision: revision, GossipCheckpointChanged: true}); err != nil {
					t.Fatalf("checkpoint after repair: %v", err)
				}
				_, againRevision, againReport, _, err := store.LoadCommon()
				if err != nil || againRevision != 2 || againReport.RootAuthorityRepaired {
					t.Fatalf("reload: revision=%d report=%+v err=%v", againRevision, againReport, err)
				}
			}

		})
	}
}
