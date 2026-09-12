package photonwindows

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// State owns the one persistent BoltStore handle and the common Store
// restored for the Windows composition root. It does not define a Windows-only
// snapshot, revision or bbolt schema.
type State struct {
	mu     sync.RWMutex
	bolt   *corestate.BoltStore
	common *corestate.Store
	close  sync.Once
	closed bool
	err    error
}

// OpenState opens an existing common-state database and restores its exact
// persisted VerifiedRevision. Linux legacy migration deliberately does not
// live here; a Windows database must already use the common schema.
func OpenState(path string, managed zone.ZonePath, trustedRoot ed25519.PublicKey, lockTimeout time.Duration) (*State, error) {
	if !managed.Valid() || managed.IsRoot() {
		return nil, errors.New("managed zone must be a valid non-root Photon zone")
	}
	if len(trustedRoot) != ed25519.PublicKeySize {
		return nil, errors.New("trusted root public key is invalid")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat Photon state %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("Photon state %s is a directory", path)
	}
	boltStore, err := corestate.OpenBoltStore(path, 0o600, lockTimeout)
	if err != nil {
		return nil, err
	}
	candidate, revision, _, found, err := boltStore.LoadCommon()
	if err != nil {
		_ = boltStore.Close()
		return nil, fmt.Errorf("load Photon common state %s: %w", path, err)
	}
	if !found {
		_ = boltStore.Close()
		return nil, fmt.Errorf("load Photon common state %s: common schema is absent", path)
	}
	if candidate == nil || candidate.Verified == nil {
		_ = boltStore.Close()
		return nil, fmt.Errorf("load Photon common state %s: verified state is absent", path)
	}
	if candidate.Verified.ManagedZone != managed {
		_ = boltStore.Close()
		return nil, fmt.Errorf("managed zone mismatch: config=%s state=%s", managed, candidate.Verified.ManagedZone)
	}
	if !bytes.Equal(candidate.Verified.TrustedRootPublicKey, trustedRoot) {
		_ = boltStore.Close()
		return nil, errors.New("trusted root public key does not match persisted state")
	}
	common, err := corestate.RestoreStore(candidate, revision, boltStore.CommitCommon)
	if err != nil {
		_ = boltStore.Close()
		return nil, fmt.Errorf("restore Photon common state %s: %w", path, err)
	}
	return &State{bolt: boltStore, common: common}, nil
}

// Store returns the shared in-memory verified Store. Callers must not close it;
// State owns the combined common/Bolt lifecycle.
func (source *State) Store() *corestate.Store {
	if source == nil {
		return nil
	}
	source.mu.RLock()
	defer source.mu.RUnlock()
	if source.closed {
		return nil
	}
	return source.common
}

func (source *State) ReadView(ctx context.Context) (corestate.View, error) {
	if source == nil {
		return corestate.View{}, corestate.ErrVerifiedStoreClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return corestate.View{}, err
	}
	source.mu.RLock()
	defer source.mu.RUnlock()
	if source.closed || source.common == nil {
		return corestate.View{}, corestate.ErrVerifiedStoreClosed
	}
	return source.common.ReadView(), nil
}

func (source *State) Close() error {
	if source == nil {
		return nil
	}
	source.close.Do(func() {
		source.mu.Lock()
		source.closed = true
		if source.common != nil {
			source.common.Close()
		}
		if source.bolt != nil {
			source.err = source.bolt.Close()
		}
		source.mu.Unlock()
	})
	return source.err
}
