package photonproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// The grace period triples the longest time a v2 nonce can be live.
const v2ReplayLimit = 3 * delegationReplayLimit

var (
	v2ReplayBucket = []byte("proxy-v2-replay")
	v2ReplayNonces = []byte("nonces")
	v2ReplayExpiry = []byte("expiry")
	v2ReplayCutoff = []byte("upgrade-cutoff")
	v2ReplayPruned = []byte("pruned-through")
)

type v2Replay struct {
	db *routeState
}

func newV2Replay(db *routeState, now time.Time, upgrade bool) (*v2Replay, error) {
	err := db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(v2ReplayBucket) != nil {
			return nil
		}
		bucket, err := tx.CreateBucket(v2ReplayBucket)
		if err != nil {
			return err
		}
		if _, err := bucket.CreateBucket(v2ReplayNonces); err != nil {
			return err
		}
		if _, err := bucket.CreateBucket(v2ReplayExpiry); err != nil {
			return err
		}
		if upgrade {
			// The old process kept its cache in memory and accepted signatures
			// dated up to two seconds ahead. Reject that range on conversion.
			return bucket.Put(v2ReplayCutoff, binary.BigEndian.AppendUint64(nil, uint64(now.Add(2*time.Second).UnixMilli())))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("initialize Photon Proxy replay state: %w", err)
	}
	return &v2Replay{db: db}, nil
}

func (r *v2Replay) consume(grant v2Grant, now time.Time) (bool, error) {
	nowMS, until := uint64(now.UnixMilli()), uint64(grant.acceptUntil().UnixMilli())
	key := []byte(string(grant.origin) + "\x00" + grant.nonce)
	accepted := false
	// Concurrent CONNECTs can share a durable commit. Batch may call this
	// closure again after rolling back an earlier attempt.
	err := r.db.Batch(func(tx *bolt.Tx) error {
		accepted = false
		bucket := tx.Bucket(v2ReplayBucket)
		if bucket == nil {
			return errors.New("missing Proxy v2 replay bucket")
		}
		nonces, expiry := bucket.Bucket(v2ReplayNonces), bucket.Bucket(v2ReplayExpiry)
		if nonces == nil || expiry == nil {
			return errors.New("missing Proxy v2 replay index")
		}
		cutoff, err := v2ReplayTime(bucket, v2ReplayCutoff)
		if err != nil {
			return err
		}
		pruned, err := v2ReplayTime(bucket, v2ReplayPruned)
		if err != nil {
			return err
		}
		if until <= max(nowMS, pruned) || uint64(grant.issued.UnixMilli()) <= cutoff {
			return nil
		}

		count := nonces.Sequence()
		lastPruned := pruned
		cursor := expiry.Cursor()
		for oldest, _ := cursor.First(); oldest != nil; oldest, _ = cursor.First() {
			if len(oldest) <= 8 || count == 0 {
				return errors.New("invalid Proxy v2 replay expiry index")
			}
			deadline := binary.BigEndian.Uint64(oldest)
			if deadline > nowMS {
				break
			}
			if err := nonces.Delete(oldest[8:]); err != nil {
				return err
			}
			if err := cursor.Delete(); err != nil {
				return err
			}
			count--
			lastPruned = max(lastPruned, deadline)
		}
		if lastPruned != pruned {
			if err := bucket.Put(v2ReplayPruned, binary.BigEndian.AppendUint64(nil, lastPruned)); err != nil {
				return err
			}
		}
		if nonces.Get(key) != nil || count >= v2ReplayLimit {
			return nonces.SetSequence(count)
		}
		deadline := binary.BigEndian.AppendUint64(nil, until)
		if err := nonces.Put(key, deadline); err != nil {
			return err
		}
		if err := expiry.Put(append(deadline, key...), nil); err != nil {
			return err
		}
		accepted = true
		return nonces.SetSequence(count + 1)
	})
	return accepted && err == nil, err
}

func v2ReplayTime(bucket *bolt.Bucket, key []byte) (uint64, error) {
	value := bucket.Get(key)
	if value == nil {
		return 0, nil
	}
	if len(value) != 8 {
		return 0, errors.New("invalid Proxy v2 replay timestamp")
	}
	return binary.BigEndian.Uint64(value), nil
}
