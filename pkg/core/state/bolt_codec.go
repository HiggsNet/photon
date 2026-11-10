package state

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/HiggsNet/photon/pkg/core/zone"
	bolt "go.etcd.io/bbolt"
)

const BoltSchemaVersion uint64 = 2

var (
	ErrBoltStateCorrupt      = errors.New("common bbolt state is corrupt")
	ErrBoltSchemaUnsupported = errors.New("common bbolt schema is unsupported")
	ErrBoltRevisionInvalid   = errors.New("common bbolt verified revision is invalid")
	ErrTrustedRootPinChange  = errors.New("trusted root public key cannot change in an online state transaction")
)

var (
	bucketCommonState   = []byte("photon:common-state")
	bucketCommonMeta    = []byte("meta")
	bucketVerified      = []byte("verified")
	bucketVerifiedZones = []byte("zones")
	bucketGossip        = []byte("gossip-checkpoint")

	keySchemaVersion    = []byte("schema-version")
	keyVerifiedRevision = []byte("verified-revision")
	keyPayload          = []byte("payload")
)

// BoltLoadReport records recoverable damage. Verified state, schema and
// verified revision failures fail closed; a gossip checkpoint is only a restart hint and may be
// discarded without weakening trust or eventual convergence.
type BoltLoadReport struct {
	GossipCheckpointDiscarded bool
}

type persistedVerifiedState struct {
	ManagedZone          zone.ZonePath      `json:"managed_zone"`
	Network              *zone.NetworkState `json:"network,omitempty"` // reconstructed from zones
	ZonePaths            []zone.ZonePath    `json:"zone_paths,omitempty"`
	GlobalRoot           []byte             `json:"global_root"`
	TrustedRootPublicKey []byte             `json:"trusted_root_public_key,omitempty"`
	RootPrivateKey       []byte             `json:"root_private_key,omitempty"`
	IdentityPrivateKey   []byte             `json:"identity_private_key,omitempty"`
}

// LoadBoltState decodes the common state buckets from an existing platform-owned
// read transaction. found is false for an empty database.
func LoadBoltState(tx *bolt.Tx) (candidate *CommitCandidate, revision VerifiedRevision, report BoltLoadReport, found bool, err error) {
	if tx == nil {
		return nil, 0, report, false, fmt.Errorf("%w: transaction is nil", ErrBoltStateCorrupt)
	}
	common := tx.Bucket(bucketCommonState)
	if common == nil {
		return nil, 0, report, false, requireEmptyBoltState(tx)
	}
	if meta := tx.Bucket([]byte("_meta")); (meta != nil && meta.Get([]byte("cli_state")) != nil) || tx.Bucket([]byte("zone:.")) != nil {
		return nil, 0, report, true, unsupportedBoltState("legacy and current state coexist")
	}
	meta := common.Bucket(bucketCommonMeta)
	verifiedBucket := common.Bucket(bucketVerified)
	if meta == nil || verifiedBucket == nil {
		return nil, 0, report, true, fmt.Errorf("%w: required bucket is missing", ErrBoltStateCorrupt)
	}
	revision, err = loadBoltRevision(common)
	if err != nil {
		return nil, 0, report, true, err
	}

	persisted, err := loadBoltVerified(verifiedBucket)
	if err != nil {
		return nil, 0, report, true, err
	}
	verified := &VerifiedState{
		ManagedZone:          persisted.ManagedZone,
		Network:              persisted.Network,
		TrustedRootPublicKey: append([]byte(nil), persisted.TrustedRootPublicKey...),
		RootPrivateKey:       append([]byte(nil), persisted.RootPrivateKey...),
		IdentityPrivateKey:   append([]byte(nil), persisted.IdentityPrivateKey...),
	}
	if err := ValidateStateRoot(verified); err != nil {
		return nil, 0, report, true, fmt.Errorf("%w: verified payload: %v", ErrBoltStateCorrupt, err)
	}

	gossip, discarded := loadBoltCheckpoint(common.Bucket(bucketGossip))
	report.GossipCheckpointDiscarded = discarded
	return cloneCommitCandidate(verified, gossip), revision, report, true, nil
}

// CommitBoltState writes the complete common candidate into an existing
// platform-owned write transaction. It checks that verified payload changes
// advance the sole VerifiedRevision exactly once, but never commits or rolls
// back tx; the process-wide BoltStore controls the single atomic transaction.
//
// changed is false when the encoded common root is already byte-identical.
func CommitBoltState(tx *bolt.Tx, candidate *CommitCandidate, changes ChangeSet) (changed bool, err error) {
	if tx == nil || !tx.Writable() {
		return false, errors.New("common state commit requires a writable bbolt transaction")
	}
	if candidate == nil || candidate.Verified == nil {
		return false, fmt.Errorf("%w: verified candidate is missing", ErrInvalidStateRoot)
	}
	if err := ValidateStateRoot(candidate.Verified); err != nil {
		return false, err
	}
	encoded, err := encodeBoltVerified(candidate.Verified)
	if err != nil {
		return false, err
	}

	common := tx.Bucket(bucketCommonState)
	if common != nil {
		verifiedBucket := common.Bucket(bucketVerified)
		if verifiedBucket == nil {
			return false, fmt.Errorf("%w: verified bucket is missing", ErrBoltStateCorrupt)
		}
		current, err := loadBoltRevision(common)
		if err != nil {
			return false, err
		}
		var currentPersisted persistedVerifiedState
		if err := decodeRequiredJSON(verifiedBucket, keyPayload, &currentPersisted); err != nil {
			return false, err
		}
		if !bytes.Equal(currentPersisted.TrustedRootPublicKey, candidate.Verified.TrustedRootPublicKey) {
			return false, ErrTrustedRootPinChange
		}
		if currentPersisted.Network != nil {
			return false, fmt.Errorf("%w: unexpected aggregate verified payload", ErrBoltStateCorrupt)
		}
		verifiedChanged, err := encoded.differsFrom(verifiedBucket)
		if err != nil {
			return false, err
		}
		wantRevision := current
		if verifiedChanged {
			wantRevision++
		}
		if changes.VerifiedRevision != wantRevision {
			return false, fmt.Errorf("%w: payload change=%v requires %d, got %d", ErrBoltRevisionInvalid, verifiedChanged, wantRevision, changes.VerifiedRevision)
		}
	} else if err := requireEmptyBoltState(tx); err != nil {
		return false, err
	}

	common, created, err := createBucketIfMissing(tx, bucketCommonState)
	if err != nil {
		return false, err
	}
	changed = created
	meta, created, err := createNestedBucketIfMissing(common, bucketCommonMeta)
	if err != nil {
		return false, err
	}
	changed = changed || created
	verifiedBucket, created, err := createNestedBucketIfMissing(common, bucketVerified)
	if err != nil {
		return false, err
	}
	changed = changed || created
	gossipBucket, created, err := createNestedBucketIfMissing(common, bucketGossip)
	if err != nil {
		return false, err
	}
	changed = changed || created

	verifiedChanged, err := encoded.save(verifiedBucket)
	if err != nil {
		return false, err
	}
	changed = changed || verifiedChanged
	checkpointChanged, err := replaceBoltCheckpoint(gossipBucket, candidate.Gossip)
	if err != nil {
		return false, err
	}
	changed = changed || checkpointChanged
	for _, value := range []struct {
		key   []byte
		value uint64
	}{
		{keySchemaVersion, BoltSchemaVersion},
		{keyVerifiedRevision, uint64(changes.VerifiedRevision)},
	} {
		fieldChanged, err := putUint64IfChanged(meta, value.key, value.value)
		if err != nil {
			return false, err
		}
		changed = changed || fieldChanged
	}
	return changed, nil
}

func loadBoltRevision(common *bolt.Bucket) (VerifiedRevision, error) {
	meta := common.Bucket(bucketCommonMeta)
	if meta == nil {
		return 0, fmt.Errorf("%w: meta bucket is missing", ErrBoltStateCorrupt)
	}
	version, err := decodeRequiredUint64(meta, keySchemaVersion)
	if err != nil {
		return 0, err
	}
	if version < BoltSchemaVersion {
		return 0, unsupportedBoltState(fmt.Sprintf("schema %d, want %d", version, BoltSchemaVersion))
	}
	if version > BoltSchemaVersion {
		return 0, fmt.Errorf("%w: schema %d, want %d", ErrBoltSchemaUnsupported, version, BoltSchemaVersion)
	}
	verified, err := decodeRequiredUint64(meta, keyVerifiedRevision)
	if err != nil {
		return 0, err
	}
	return VerifiedRevision(verified), nil
}

func requireEmptyBoltState(tx *bolt.Tx) error {
	if key, _ := tx.Cursor().First(); key != nil {
		return unsupportedBoltState("common schema is absent")
	}
	return nil
}

func unsupportedBoltState(detail string) error {
	return fmt.Errorf("%w: %s; open the database with Photon v0.6.6 to upgrade it first", ErrBoltSchemaUnsupported, detail)
}

func createBucketIfMissing(tx *bolt.Tx, name []byte) (*bolt.Bucket, bool, error) {
	if bucket := tx.Bucket(name); bucket != nil {
		return bucket, false, nil
	}
	bucket, err := tx.CreateBucket(name)
	return bucket, err == nil, err
}

func createNestedBucketIfMissing(parent *bolt.Bucket, name []byte) (*bolt.Bucket, bool, error) {
	if bucket := parent.Bucket(name); bucket != nil {
		return bucket, false, nil
	}
	bucket, err := parent.CreateBucket(name)
	return bucket, err == nil, err
}

func putBytesIfChanged(bucket *bolt.Bucket, key, data []byte) (bool, error) {
	if bytes.Equal(bucket.Get(key), data) {
		return false, nil
	}
	return true, bucket.Put(key, data)
}

func putUint64IfChanged(bucket *bolt.Bucket, key []byte, value uint64) (bool, error) {
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], value)
	if bytes.Equal(bucket.Get(key), data[:]) {
		return false, nil
	}
	return true, bucket.Put(key, data[:])
}

func decodeRequiredUint64(bucket *bolt.Bucket, key []byte) (uint64, error) {
	data := bucket.Get(key)
	if len(data) != 8 {
		return 0, fmt.Errorf("%w: %s must be an 8-byte uint64", ErrBoltStateCorrupt, key)
	}
	return binary.BigEndian.Uint64(data), nil
}

func decodeRequiredJSON(bucket *bolt.Bucket, key []byte, out any) error {
	data := bucket.Get(key)
	if data == nil {
		return fmt.Errorf("%w: %s is missing", ErrBoltStateCorrupt, key)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrBoltStateCorrupt, key, err)
	}
	return nil
}
