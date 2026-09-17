package state

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	ErrBoltStoreClosed = errors.New("bbolt state store is closed")
	errBoltNoChanges   = errors.New("bbolt state transaction has no changes")
)

type boltDB interface {
	View(func(*bolt.Tx) error) error
	Update(func(*bolt.Tx) error) error
	Close() error
}

// BoltStore is the sole persistent state owner for one process. Logical state
// partitions use separate bucket codecs, but share this handle, transaction
// ordering and close lifecycle.
type BoltStore struct {
	mu     sync.Mutex
	db     boltDB
	closed bool
}

func OpenBoltStore(path string, mode os.FileMode, lockTimeout time.Duration) (*BoltStore, error) {
	if path == "" {
		return nil, errors.New("bbolt state path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, mode, &bolt.Options{Timeout: lockTimeout})
	if err != nil {
		return nil, fmt.Errorf("open bbolt state %s: %w", path, err)
	}
	return &BoltStore{db: db}, nil
}

// View executes a read transaction using the store-owned handle.
func (store *BoltStore) View(read func(*bolt.Tx) error) error {
	if read == nil {
		return errors.New("bbolt state read function is nil")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed || store.db == nil {
		return ErrBoltStoreClosed
	}
	return store.db.View(read)
}

// LoadCommon loads common state and atomically persists any startup root repair.
func (store *BoltStore) LoadCommon() (*CommitCandidate, VerifiedRevision, BoltLoadReport, bool, error) {
	var candidate *CommitCandidate
	var revision VerifiedRevision
	var report BoltLoadReport
	found := false
	err := store.Update(func(tx *bolt.Tx) (bool, error) {
		var err error
		candidate, revision, report, found, err = LoadBoltState(tx)
		if err != nil || !found || !report.RootAuthorityRepaired {
			return false, err
		}
		revision++
		return CommitBoltState(tx, candidate, ChangeSet{VerifiedRevision: revision, NetworkChanged: true, SecurityPriority: true})
	})
	return candidate, revision, report, found, err
}

// Update composes logical bucket codecs in one transaction. update reports
// whether it changed bytes; false rolls the transaction back as a successful
// no-op so bbolt does not commit a new transaction.
func (store *BoltStore) Update(update func(*bolt.Tx) (bool, error)) error {
	if update == nil {
		return errors.New("bbolt state update function is nil")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed || store.db == nil {
		return ErrBoltStoreClosed
	}
	err := store.db.Update(func(tx *bolt.Tx) error {
		changed, err := update(tx)
		if err != nil {
			return err
		}
		if !changed {
			return errBoltNoChanges
		}
		return nil
	})
	if errors.Is(err, errBoltNoChanges) {
		return nil
	}
	return err
}

// CommitCommon is the commit callback used by the in-memory common Store.
func (store *BoltStore) CommitCommon(ctx context.Context, candidate *CommitCandidate, changes ChangeSet) error {
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
		return CommitBoltState(tx, candidate, changes)
	})
}

func (store *BoltStore) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	if store.db == nil {
		return nil
	}
	return store.db.Close()
}
