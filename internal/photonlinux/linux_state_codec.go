package photonlinux

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	bolt "go.etcd.io/bbolt"
)

const (
	linuxStateSchemaVersion uint64 = 1
	LinuxStateBucketName           = "photon:linux-runtime"
)

var (
	linuxStateBucket                    = []byte(LinuxStateBucketName)
	linuxStateSchemaKey                 = []byte("schema-version")
	linuxStatePayloadKey                = []byte("payload")
	ErrLinuxStateCorrupt                = errors.New("linux state is corrupt")
	ErrLinuxStateSourceRevisionMismatch = errors.New("linux state source verified revision does not match current state")
)

// LoadLinuxStateTx reads the Linux partition from a platform-owned Bolt
// transaction. Missing state is distinct from malformed state.
func LoadLinuxStateTx(tx *bolt.Tx) (*LinuxState, bool, error) {
	if tx == nil {
		return nil, false, errors.New("linux state load transaction is nil")
	}
	bucket := tx.Bucket(linuxStateBucket)
	if bucket == nil {
		return nil, false, nil
	}
	version := bucket.Get(linuxStateSchemaKey)
	if len(version) != 8 || binary.BigEndian.Uint64(version) != linuxStateSchemaVersion {
		return nil, true, fmt.Errorf("%w: unsupported schema", ErrLinuxStateCorrupt)
	}
	payload := bucket.Get(linuxStatePayloadKey)
	if payload == nil {
		return nil, true, fmt.Errorf("%w: payload is missing", ErrLinuxStateCorrupt)
	}
	if bytes.Equal(bytes.TrimSpace(payload), []byte("null")) {
		return nil, true, fmt.Errorf("%w: payload is null", ErrLinuxStateCorrupt)
	}
	var state LinuxState
	if err := json.Unmarshal(payload, &state); err != nil {
		return nil, true, fmt.Errorf("%w: %v", ErrLinuxStateCorrupt, err)
	}
	return &state, true, nil
}

// SaveLinuxStateTx writes a byte-level no-op-aware Linux partition through
// a transaction owned by the process composition root.
func SaveLinuxStateTx(tx *bolt.Tx, state *LinuxState) (bool, error) {
	if tx == nil || !tx.Writable() {
		return false, errors.New("linux state save requires a writable bbolt transaction")
	}
	if state == nil {
		return false, errors.New("linux state is nil")
	}
	bucket, err := tx.CreateBucketIfNotExists(linuxStateBucket)
	if err != nil {
		return false, err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return false, err
	}
	var version [8]byte
	binary.BigEndian.PutUint64(version[:], linuxStateSchemaVersion)
	changed := false
	for _, item := range []struct{ key, value []byte }{
		{linuxStateSchemaKey, version[:]},
		{linuxStatePayloadKey, payload},
	} {
		if bytes.Equal(bucket.Get(item.key), item.value) {
			continue
		}
		if err := bucket.Put(item.key, item.value); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, nil
}

// CommitLinuxState persists a Linux completion only when the common
// verified revision still matches the revision used to plan it.
func CommitLinuxState(store *corestate.BoltStore, sourceRevision corestate.VerifiedRevision, state *LinuxState) error {
	if store == nil {
		return errors.New("bbolt state store is nil")
	}
	return store.Update(func(tx *bolt.Tx) (bool, error) {
		_, currentRevision, _, found, err := corestate.LoadBoltState(tx)
		if err != nil {
			return false, err
		}
		if !found {
			return false, errors.New("common state is not initialized")
		}
		if sourceRevision != currentRevision {
			return false, fmt.Errorf("%w: completion=%d current=%d", ErrLinuxStateSourceRevisionMismatch, sourceRevision, currentRevision)
		}
		return SaveLinuxStateTx(tx, state)
	})
}
