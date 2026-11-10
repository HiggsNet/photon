package zone

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketMeta       = []byte("_meta")
	metaGlobalRoot   = []byte("global_root")
	keyAuthority     = []byte("authority")
	keyParentProof   = []byte("parent_proof")
	keyDelegations   = []byte("delegations")
	keyRevocations   = []byte("revocations")
	keyRecords       = []byte("records")
	keyRecordHistory = []byte("record_history")
	keyMerkleRoot    = []byte("merkle_root")
	errNoBoltChanges = errors.New("bolt store transaction has no changes")
)

type BoltStore struct {
	db *bolt.DB
}

func OpenBoltStore(path string, mode os.FileMode) (*BoltStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, mode, nil)
	if err != nil {
		return nil, err
	}
	return &BoltStore{db: db}, nil
}

func (s *BoltStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *BoltStore) SaveNetwork(ns *NetworkState) error {
	if s == nil || s.db == nil {
		return errors.New("bolt store is closed")
	}
	if ns == nil {
		return errors.New("network state is nil")
	}

	return s.updateIfChanged(func(tx *bolt.Tx) (bool, error) {
		return SaveNetworkTx(tx, ns)
	})
}

// SaveNetworkAndMetaJSON atomically persists daemon metadata and the complete
// authoritative Network in one bbolt transaction.
func (s *BoltStore) SaveNetworkAndMetaJSON(key string, value any, ns *NetworkState) error {
	if s == nil || s.db == nil {
		return errors.New("bolt store is closed")
	}
	if ns == nil {
		return errors.New("network state is nil")
	}
	return s.updateIfChanged(func(tx *bolt.Tx) (bool, error) {
		meta, created, err := createBucketIfMissing(tx, bucketMeta)
		if err != nil {
			return false, err
		}
		metaChanged, err := putJSONIfChanged(meta, []byte(key), value)
		if err != nil {
			return false, err
		}
		networkChanged, err := SaveNetworkTx(tx, ns)
		return created || metaChanged || networkChanged, err
	})
}

// SaveNetworkTx writes the legacy zone-bucket representation into a caller-
// owned transaction. It does not commit or roll back tx.
func SaveNetworkTx(tx *bolt.Tx, ns *NetworkState) (bool, error) {
	if tx == nil || !tx.Writable() {
		return false, errors.New("network save requires a writable bbolt transaction")
	}
	if ns == nil {
		return false, errors.New("network state is nil")
	}
	meta, changed, err := createBucketIfMissing(tx, bucketMeta)
	if err != nil {
		return false, err
	}
	globalRootChanged, err := putJSONIfChanged(meta, metaGlobalRoot, ns.GlobalRoot)
	if err != nil {
		return false, err
	}
	changed = changed || globalRootChanged

	var staleBuckets [][]byte
	if err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		path, ok := parseZoneBucket(name)
		if !ok {
			return nil
		}
		if ns.Zones[path] == nil {
			staleBuckets = append(staleBuckets, append([]byte(nil), name...))
		}
		return nil
	}); err != nil {
		return false, err
	}
	for _, name := range staleBuckets {
		if err := tx.DeleteBucket(name); err != nil {
			return false, err
		}
		changed = true
	}

	for path, zs := range ns.Zones {
		if zs == nil {
			continue
		}
		bucket, created, err := createBucketIfMissing(tx, zoneBucket(path))
		if err != nil {
			return false, err
		}
		changed = changed || created
		for _, field := range []struct {
			key   []byte
			value any
		}{
			{keyAuthority, zs.Authority},
			{keyParentProof, zs.ParentProof},
			{keyDelegations, zs.Delegations},
			{keyRevocations, zs.Revocations},
			{keyRecords, zs.Records},
			{keyRecordHistory, zs.RecordHistory},
			{keyMerkleRoot, zs.MerkleRoot},
		} {
			fieldChanged, err := putJSONIfChanged(bucket, field.key, field.value)
			if err != nil {
				return false, err
			}
			changed = changed || fieldChanged
		}
	}
	return changed, nil
}

func (s *BoltStore) SaveMetaJSON(key string, value any) error {
	if s == nil || s.db == nil {
		return errors.New("bolt store is closed")
	}
	return s.updateIfChanged(func(tx *bolt.Tx) (bool, error) {
		bucket, created, err := createBucketIfMissing(tx, bucketMeta)
		if err != nil {
			return false, err
		}
		changed, err := putJSONIfChanged(bucket, []byte(key), value)
		return created || changed, err
	})
}

func (s *BoltStore) updateIfChanged(update func(*bolt.Tx) (bool, error)) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		changed, err := update(tx)
		if err != nil {
			return err
		}
		if !changed {
			return errNoBoltChanges
		}
		return nil
	})
	if errors.Is(err, errNoBoltChanges) {
		return nil
	}
	return err
}

func createBucketIfMissing(tx *bolt.Tx, name []byte) (*bolt.Bucket, bool, error) {
	if bucket := tx.Bucket(name); bucket != nil {
		return bucket, false, nil
	}
	bucket, err := tx.CreateBucket(name)
	return bucket, err == nil, err
}

func (s *BoltStore) LoadMetaJSON(key string, out any) error {
	if s == nil || s.db == nil {
		return errors.New("bolt store is closed")
	}
	return s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketMeta)
		if bucket == nil {
			return nil
		}
		return getJSON(bucket, []byte(key), out)
	})
}

func (s *BoltStore) LoadNetwork() (*NetworkState, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("bolt store is closed")
	}

	var ns *NetworkState
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		ns, err = LoadNetworkTx(tx)
		return err
	})
	if err != nil {
		return nil, err
	}
	return ns, nil
}

// LoadNetworkTx reads the legacy zone-bucket representation from a caller-
// owned transaction. An absent representation returns an empty NetworkState.
func LoadNetworkTx(tx *bolt.Tx) (*NetworkState, error) {
	if tx == nil {
		return nil, errors.New("network load transaction is nil")
	}
	ns := NewNetworkState()
	if meta := tx.Bucket(bucketMeta); meta != nil {
		if err := getJSON(meta, metaGlobalRoot, &ns.GlobalRoot); err != nil {
			return nil, err
		}
	}
	if err := tx.ForEach(func(name []byte, bucket *bolt.Bucket) error {
		path, ok := parseZoneBucket(name)
		if !ok {
			return nil
		}
		zs := NewZoneState(path, nil)
		if err := getJSON(bucket, keyAuthority, &zs.Authority); err != nil {
			return err
		}
		if err := getJSON(bucket, keyParentProof, &zs.ParentProof); err != nil {
			return err
		}
		if err := getJSON(bucket, keyDelegations, &zs.Delegations); err != nil {
			return err
		}
		if err := getJSON(bucket, keyRevocations, &zs.Revocations); err != nil {
			return err
		}
		if err := getJSON(bucket, keyRecords, &zs.Records); err != nil {
			return err
		}
		if err := getJSON(bucket, keyRecordHistory, &zs.RecordHistory); err != nil {
			return err
		}
		if err := getJSON(bucket, keyMerkleRoot, &zs.MerkleRoot); err != nil {
			return err
		}
		normalizeZoneState(zs)
		ns.Zones[path] = zs
		return nil
	}); err != nil {
		return nil, err
	}
	return ns, nil
}

func zoneBucket(path ZonePath) []byte {
	return []byte("zone:" + path.String())
}

func parseZoneBucket(name []byte) (ZonePath, bool) {
	const prefix = "zone:"
	if len(name) <= len(prefix) || string(name[:len(prefix)]) != prefix {
		return "", false
	}
	path := ZonePath(string(name[len(prefix):]))
	return path, path.Valid()
}

func putJSONIfChanged(bucket *bolt.Bucket, key []byte, value any) (bool, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return false, err
	}
	if bytes.Equal(bucket.Get(key), data) {
		return false, nil
	}
	return true, bucket.Put(key, data)
}

func getJSON(bucket *bolt.Bucket, key []byte, out any) error {
	data := bucket.Get(key)
	if data == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s: %w", string(key), err)
	}
	return nil
}

func normalizeZoneState(zs *ZoneState) {
	if zs.Delegations == nil {
		zs.Delegations = make(map[ZonePath]*Delegation)
	}
	if zs.Revocations == nil {
		zs.Revocations = make(map[ZonePath]*DelegationRevocation)
	}
	if zs.Records == nil {
		zs.Records = make(map[string]*Record)
	}
	if zs.RecordHistory == nil {
		zs.RecordHistory = make(map[string][]*Record)
		return
	}
	for key, history := range zs.RecordHistory {
		zs.RecordHistory[key] = boundRecordHistory(history)
	}
}
