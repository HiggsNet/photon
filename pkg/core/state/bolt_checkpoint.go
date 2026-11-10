package state

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	bolt "go.etcd.io/bbolt"
)

var bucketCheckpointPeers = []byte("peers")

// loadBoltCheckpoint reads peer entries and discards the old aggregate hints.
func loadBoltCheckpoint(bucket *bolt.Bucket) (*GossipCheckpoint, bool) {
	out := &GossipCheckpoint{Peers: make(map[string]PeerCheckpoint)}
	if bucket == nil {
		return out, false
	}
	discarded := bucket.Get(keyPayload) != nil
	peers := bucket.Bucket(bucketCheckpointPeers)
	if peers == nil {
		return out, discarded
	}
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

// replaceBoltCheckpoint writes a checkpoint in a full state transaction.
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
		if peerCheckpointEmpty(restartPeerCheckpoint(checkpoint.Peers[string(k)])) {
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
	for id, peer := range checkpoint.Peers {
		if !peerCheckpointEmpty(restartPeerCheckpoint(peer)) {
			ids = append(ids, id)
		}
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
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.updateLocked(func(tx *bolt.Tx) (bool, error) {
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
