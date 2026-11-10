package state

import (
	"bytes"

	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
	bolt "go.etcd.io/bbolt"
)

// Encode the actual schema-1 shape, without the schema-2 manifest or root key.
func seedSchema1BoltState(t *testing.T, db *bolt.DB, candidate *CommitCandidate, revision VerifiedRevision) {
	t.Helper()
	payload, err := json.Marshal(struct {
		ManagedZone          zone.ZonePath      `json:"managed_zone"`
		Network              *zone.NetworkState `json:"network"`
		TrustedRootPublicKey []byte             `json:"trusted_root_public_key,omitempty"`
		RootPrivateKey       []byte             `json:"root_private_key,omitempty"`
		IdentityPrivateKey   []byte             `json:"identity_private_key,omitempty"`
	}{candidate.Verified.ManagedZone, candidate.Verified.Network, candidate.Verified.TrustedRootPublicKey, candidate.Verified.RootPrivateKey, candidate.Verified.IdentityPrivateKey})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := json.Marshal(candidate.Gossip)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		common, err := tx.CreateBucket(bucketCommonState)
		if err != nil {
			return err
		}
		meta, err := common.CreateBucket(bucketCommonMeta)
		if err != nil {
			return err
		}
		verified, err := common.CreateBucket(bucketVerified)
		if err != nil {
			return err
		}
		gossip, err := common.CreateBucket(bucketGossip)
		if err != nil {
			return err
		}
		if err := putUint64Raw(meta, keySchemaVersion, 1); err != nil {
			return err
		}
		if err := putUint64Raw(meta, keyVerifiedRevision, uint64(revision)); err != nil {
			return err
		}
		if err := verified.Put(keyPayload, payload); err != nil {
			return err
		}
		return gossip.Put(keyPayload, checkpoint)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSchema1DatabaseRejectedWithoutWriting(t *testing.T) {
	db := openCommonBoltTestDB(t)
	candidate := commonBoltTestCandidate(1)
	seedSchema1BoltState(t, db, candidate, 7)
	writes := db.Stats().TxStats.Write
	store := &BoltStore{db: db}
	if _, _, _, _, err := store.LoadCommon(); !errors.Is(err, ErrBoltSchemaUnsupported) {
		t.Fatalf("load schema 1: %v", err)
	}
	if err := store.CommitCommon(t.Context(), candidate, ChangeSet{VerifiedRevision: 7}); !errors.Is(err, ErrBoltSchemaUnsupported) {
		t.Fatalf("write schema 1: %v", err)
	}
	if db.Stats().TxStats.Write != writes {
		t.Fatal("unsupported schema was rewritten")
	}
}

func TestVerifiedZoneDeltaAndRollbackPreserveUnchangedData(t *testing.T) {
	db := openCommonBoltTestDB(t)
	candidate := checkpointBenchmarkCandidate()
	commitCommonBoltTestState(t, db, candidate, 1)
	var unchanged []byte
	if err := db.View(func(tx *bolt.Tx) error {
		unchanged = append([]byte(nil), tx.Bucket(bucketCommonState).Bucket(bucketVerified).Bucket(bucketVerifiedZones).Get([]byte("node-1.catofes."))...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	next := cloneCommitCandidate(candidate.Verified, candidate.Gossip)
	next.Verified.Network.Zones["node-0.catofes."].Records["record-0"].Value[0] = 1
	delete(next.Verified.Network.Zones, "node-2.catofes.")
	next.Gossip.Peers["peer-a"] = PeerCheckpoint{BackoffUntilUnix: 99}
	want := errors.New("injected failure after common and platform writes")
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := CommitBoltState(tx, next, ChangeSet{VerifiedRevision: 2, NetworkChanged: true}); err != nil {
			return err
		}
		platform, err := tx.CreateBucket([]byte("platform-fixture"))
		if err != nil {
			return err
		}
		if err := platform.Put([]byte("intent"), []byte("new")); err != nil {
			return err
		}
		return want
	}); !errors.Is(err, want) {
		t.Fatalf("rollback error=%v", err)
	}
	if err := db.View(func(tx *bolt.Tx) error {
		loaded, revision, _, _, err := LoadBoltState(tx)
		if err != nil {
			return err
		}
		if revision != 1 || !reflect.DeepEqual(loaded, cloneCommitCandidate(candidate.Verified, candidate.Gossip)) || tx.Bucket([]byte("platform-fixture")) != nil {
			t.Fatal("failed multi-zone transaction published partial state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	commitCommonBoltTestState(t, db, next, 2)
	if err := db.View(func(tx *bolt.Tx) error {
		zones := tx.Bucket(bucketCommonState).Bucket(bucketVerified).Bucket(bucketVerifiedZones)
		if !bytes.Equal(unchanged, zones.Get([]byte("node-1.catofes."))) || zones.Get([]byte("node-2.catofes.")) != nil {
			t.Fatal("zone delta changed unrelated data or retained deleted zone")
		}
		loaded, revision, _, _, err := LoadBoltState(tx)
		if err != nil {
			return err
		}
		if revision != 2 || !reflect.DeepEqual(loaded, cloneCommitCandidate(next.Verified, next.Gossip)) {
			t.Fatal("delta did not round-trip complete state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifiedZoneLayoutFailsClosedOnMissingMalformedOrOrphanedData(t *testing.T) {
	for _, mode := range []string{"missing", "malformed", "wrong_path", "orphan", "duplicate_manifest"} {
		t.Run(mode, func(t *testing.T) {
			db := openCommonBoltTestDB(t)
			commitCommonBoltTestState(t, db, checkpointBenchmarkCandidate(), 1)
			if err := db.Update(func(tx *bolt.Tx) error {
				root := tx.Bucket(bucketCommonState).Bucket(bucketVerified)
				zones := root.Bucket(bucketVerifiedZones)
				key := []byte("node-0.catofes.")
				switch mode {
				case "missing":
					return zones.Delete(key)
				case "malformed":
					return zones.Put(key, []byte("{"))
				case "wrong_path":
					data, _ := json.Marshal(zone.NewZoneState("other.catofes.", nil))
					return zones.Put(key, data)
				case "orphan":
					return zones.Put([]byte("orphan.catofes."), []byte("null"))
				default:
					var persisted persistedVerifiedState
					if err := decodeRequiredJSON(root, keyPayload, &persisted); err != nil {
						return err
					}
					persisted.ZonePaths = append(persisted.ZonePaths, persisted.ZonePaths[0])
					data, err := json.Marshal(persisted)
					if err != nil {
						return err
					}
					return root.Put(keyPayload, data)
				}
			}); err != nil {
				t.Fatal(err)
			}
			if err := db.View(func(tx *bolt.Tx) error { _, _, _, _, err := LoadBoltState(tx); return err }); !errors.Is(err, ErrBoltStateCorrupt) {
				t.Fatalf("corrupt layout accepted: %v", err)
			}
		})
	}
}
