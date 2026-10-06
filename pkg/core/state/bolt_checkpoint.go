package state

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	bolt "go.etcd.io/bbolt"
)

var bucketCheckpointPeers = []byte("peers")

// Legacy payload takes precedence: an older binary may have written it after
// a downgrade. Old binaries safely see an empty (loss-tolerant) checkpoint when
// only the peer bucket exists. Verified schema and data are unchanged.
func loadBoltCheckpoint(bucket *bolt.Bucket) (*GossipCheckpoint, bool) {
	out := &GossipCheckpoint{Peers: make(map[string]PeerCheckpoint)}
	if bucket == nil {
		return out, false
	}
	if data := bucket.Get(keyPayload); data != nil {
		if json.Unmarshal(data, out) != nil {
			return &GossipCheckpoint{Peers: make(map[string]PeerCheckpoint)}, true
		}
		return cloneGossipCheckpoint(out), false
	}
	peers := bucket.Bucket(bucketCheckpointPeers)
	if peers == nil {
		return out, false
	}
	discarded := false
	_ = peers.ForEach(func(k, v []byte) error {
		var peer PeerCheckpoint
		if len(k) == 0 || v == nil || json.Unmarshal(v, &peer) != nil {
			discarded = true
			return nil
		}
		out.Peers[string(k)] = peer
		return nil
	})
	return out, discarded
}

// replaceBoltCheckpoint is used only for full network/checkpoint transactions
// and one-time legacy conversion. Steady-state hints use CommitCheckpoints.
func replaceBoltCheckpoint(bucket *bolt.Bucket, checkpoint *GossipCheckpoint) (bool, error) {
	peers, changed, err := createNestedBucketIfMissing(bucket, bucketCheckpointPeers)
	if err != nil {
		return false, err
	}
	if checkpoint == nil {
		checkpoint = &GossipCheckpoint{}
	}
	var remove [][]byte
	if err := peers.ForEach(func(k, v []byte) error {
		if _, ok := checkpoint.Peers[string(k)]; !ok {
			remove = append(remove, append([]byte(nil), k...))
		}
		return nil
	}); err != nil {
		return false, err
	}
	for _, key := range remove {
		if err := peers.Delete(key); err != nil {
			return false, err
		}
		changed = true
	}
	ids := make([]string, 0, len(checkpoint.Peers))
	for id := range checkpoint.Peers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		data, err := json.Marshal(checkpoint.Peers[id])
		if err != nil {
			return false, err
		}
		wrote, err := putBytesIfChanged(peers, []byte(id), data)
		if err != nil {
			return false, err
		}
		changed = changed || wrote
	}
	if bucket.Get(keyPayload) != nil {
		if err := bucket.Delete(keyPayload); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, nil
}

// CommitCheckpoints never loads, clones, encodes or writes verified payloads.
// The same owner and write transaction serialize it with full state commits.
func (store *BoltStore) CommitCheckpoints(ctx context.Context, updates map[string]*PeerCheckpoint, revision VerifiedRevision) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.Update(func(tx *bolt.Tx) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		common := tx.Bucket(bucketCommonState)
		if common == nil {
			return false, fmt.Errorf("%w: common root missing", ErrBoltStateCorrupt)
		}
		current, err := loadBoltRevision(common)
		if err != nil {
			return false, err
		}
		if current != revision {
			return false, ErrBoltRevisionInvalid
		}
		if len(updates) == 0 {
			return false, nil
		}
		bucket, changed, err := createNestedBucketIfMissing(common, bucketGossip)
		if err != nil {
			return false, err
		}
		if bucket.Get(keyPayload) != nil {
			checkpoint, _ := loadBoltCheckpoint(bucket)
			migrated, err := replaceBoltCheckpoint(bucket, checkpoint)
			if err != nil {
				return false, err
			}
			changed = changed || migrated
		}
		peers, created, err := createNestedBucketIfMissing(bucket, bucketCheckpointPeers)
		if err != nil {
			return false, err
		}
		changed = changed || created
		ids := make([]string, 0, len(updates))
		for id := range updates {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if id == "" {
				return false, fmt.Errorf("checkpoint peer id is empty")
			}
			peer := updates[id]
			if peer == nil {
				if peers.Get([]byte(id)) != nil {
					if err := peers.Delete([]byte(id)); err != nil {
						return false, err
					}
					changed = true
				}
				continue
			}
			data, err := json.Marshal(peer)
			if err != nil {
				return false, err
			}
			wrote, err := putBytesIfChanged(peers, []byte(id), data)
			if err != nil {
				return false, err
			}
			changed = changed || wrote
		}
		return changed, nil
	})
}
