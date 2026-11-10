package state

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucketCheckpointPeers = []byte("peers")

const checkpointRefreshInterval = 5 * time.Second

// Only a forward renewal of an existing observed path can wait for the batch.
func isCheckpointRefresh(previous, next PeerCheckpoint) bool {
	if previous.ObservedUntilUnix <= 0 || next.ObservedUntilUnix <= previous.ObservedUntilUnix {
		return false
	}
	previous.ObservedUntilUnix = next.ObservedUntilUnix
	return reflect.DeepEqual(previous, next)
}

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
	store.mu.Lock()
	defer store.mu.Unlock()
	var queued map[string]PeerCheckpoint
	var flushed bool
	err := store.updateLocked(func(tx *bolt.Tx) (bool, error) {
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
			previous, pending := store.checkpointRefreshes[id]
			pending = pending && store.checkpointRevision == revision
			valid := pending
			if !pending {
				previous = PeerCheckpoint{}
				valid = json.Unmarshal(peers.Get([]byte(id)), &previous) == nil
			}
			if valid && (isCheckpointRefresh(previous, *peer) || (pending && reflect.DeepEqual(previous, *peer))) {
				if queued == nil {
					queued = make(map[string]PeerCheckpoint)
				}
				queued[id] = clonePeerCheckpoint(*peer)
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
		if changed {
			// The immediate commit is already paying for a sync. Include
			// pending refreshes, with the current updates taking precedence.
			if store.checkpointRevision == revision {
				if _, err := writeCheckpointRefreshes(peers, store.checkpointRefreshes, updates); err != nil {
					return false, err
				}
			}
			if _, err := writeCheckpointRefreshes(peers, queued, nil); err != nil {
				return false, err
			}
			flushed = true
		}
		return changed, nil
	})
	if err != nil {
		return err
	}
	if store.checkpointRevision != revision {
		clear(store.checkpointRefreshes)
		store.checkpointRevision = revision
	}
	if flushed {
		clear(store.checkpointRefreshes)
		return nil
	}
	for id := range updates {
		delete(store.checkpointRefreshes, id)
	}
	for id, peer := range queued {
		if store.checkpointRefreshes == nil {
			store.checkpointRefreshes = make(map[string]PeerCheckpoint)
		}
		store.checkpointRefreshes[id] = peer
	}
	store.scheduleCheckpointFlushLocked()
	return nil
}

func (store *BoltStore) scheduleCheckpointFlushLocked() {
	if store.checkpointTimer != nil || len(store.checkpointRefreshes) == 0 {
		return
	}
	store.checkpointTimer = time.AfterFunc(checkpointRefreshInterval, func() {
		store.mu.Lock()
		defer store.mu.Unlock()
		store.checkpointTimer = nil
		if store.closed {
			return
		}
		if err := store.flushCheckpointRefreshesLocked(); err != nil {
			slog.Warn("flush gossip checkpoint refreshes", "error", err)
			store.scheduleCheckpointFlushLocked()
		}
	})
}

func (store *BoltStore) flushCheckpointRefreshesLocked() error {
	if len(store.checkpointRefreshes) == 0 {
		return nil
	}
	err := store.updateLocked(func(tx *bolt.Tx) (bool, error) {
		common := tx.Bucket(bucketCommonState)
		if common == nil {
			return false, nil
		}
		revision, err := loadBoltRevision(common)
		if err != nil || revision != store.checkpointRevision {
			return false, err
		}
		bucket := common.Bucket(bucketGossip)
		if bucket == nil || bucket.Get(keyPayload) != nil {
			return false, nil
		}
		peers := bucket.Bucket(bucketCheckpointPeers)
		if peers == nil {
			return false, nil
		}
		return writeCheckpointRefreshes(peers, store.checkpointRefreshes, nil)
	})
	if err == nil {
		clear(store.checkpointRefreshes)
	}
	return err
}

func writeCheckpointRefreshes(peers *bolt.Bucket, pending map[string]PeerCheckpoint, superseded map[string]*PeerCheckpoint) (bool, error) {
	changed := false
	for id, peer := range pending {
		if _, ok := superseded[id]; ok {
			continue
		}
		key := []byte(id)
		var persisted PeerCheckpoint
		// The refresh may already have been persisted or superseded.
		if json.Unmarshal(peers.Get(key), &persisted) != nil || !isCheckpointRefresh(persisted, peer) {
			continue
		}
		data, err := json.Marshal(peer)
		if err != nil {
			return false, err
		}
		if err := peers.Put(key, data); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, nil
}
