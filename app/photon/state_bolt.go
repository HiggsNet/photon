package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	bolt "go.etcd.io/bbolt"
)

func applyOfflineCommonIntent(rt *AppContext, intent corestate.LocalIntent, dryRun bool) (corestate.LocalIntentResult, error) {
	state, err := openState(rt)
	if err != nil {
		return corestate.LocalIntentResult{}, err
	}
	defer state.Close()
	if dryRun {
		return state.Common.PreviewLocalIntent(intent, rt.Now())
	}
	return state.Common.ApplyLocalIntent(context.Background(), intent, rt.Now())
}

// loadOfflineOwnerViews runs the same one-way schema migration as daemon
// startup, then closes the shared Bolt handle and returns detached snapshots
// of the two persisted owners. This is only the fallback for an unavailable
// daemon or an explicit direct operation; online readers use command-oriented
// control views and never contend for the daemon's Bolt handle.
func loadOfflineOwnerViews(rt *AppContext) (corestate.View, *photonlinux.LinuxState, error) {
	state, err := openState(rt)
	if err != nil {
		return corestate.View{}, nil, err
	}
	view := state.Common.ReadView()
	linuxState := state.ReadLinux()
	if err := state.Close(); err != nil {
		return corestate.View{}, nil, err
	}
	return view, linuxState, nil
}

const daemonBoltLockTimeout = time.Second

func openState(rt *AppContext) (*State, error) {
	if rt == nil || rt.Config == nil || rt.StatePath == "" {
		return nil, errors.New("state path is not configured")
	}
	store, err := corestate.OpenBoltStore(rt.StatePath, 0o600, daemonBoltLockTimeout)
	if err != nil {
		return nil, err
	}
	state, found, err := restoreState(store, rt.Config.TrustedRootPublicKey)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	if !found {
		// Only an uninitialized database may enter the pending identity bootstrap
		// path. Existing legacy databases were already migrated by the first call.
		// The bootstrap writer initializes the current common/Linux partitions with
		// an authority-less managed-zone placeholder; no temporary legacy schema is
		// created for a new node.
		if err := store.Close(); err != nil {
			return nil, err
		}
		if err := writeConfiguredPendingBootstrap(rt.StatePath, rt.Config); err != nil {
			return nil, err
		}
		store, err = corestate.OpenBoltStore(rt.StatePath, 0o600, daemonBoltLockTimeout)
		if err != nil {
			return nil, err
		}
		state, found, err = restoreState(store, rt.Config.TrustedRootPublicKey)
		if err != nil || !found {
			_ = store.Close()
			if err != nil {
				return nil, err
			}
			return nil, errors.New("state is not initialized")
		}
	}
	if err := validateConfiguredIdentityState(state.Common.ReadView().State, rt.Config); err != nil {
		_ = state.Close()
		return nil, err
	}
	return state, nil
}

func loadStateTx(tx *bolt.Tx) (*corestate.CommitCandidate, corestate.VerifiedRevision, *photonlinux.LinuxState, bool, error) {
	candidate, revision, _, found, err := corestate.LoadBoltState(tx)
	if err != nil || !found {
		return nil, 0, nil, found, err
	}
	linuxState, linuxStateFound, err := photonlinux.LoadLinuxStateTx(tx)
	if err != nil {
		return nil, 0, nil, false, err
	}
	if !linuxStateFound {
		return nil, 0, nil, false, fmt.Errorf("%w: Linux state bucket is missing", photonlinux.ErrLinuxStateCorrupt)
	}
	return candidate, revision, linuxState, true, nil
}

// restoreState performs the complete persistent startup boundary:
// it upgrades a legacy database when necessary, loads both logical partitions
// through one BoltStore transaction, restores Common, and returns the complete
// owner of that Bolt handle. No raw persistent partition escapes this boundary.
func restoreState(store *corestate.BoltStore, trustedRoot ed25519.PublicKey) (*State, bool, error) {
	if store == nil {
		return nil, false, errors.New("bbolt state store is nil")
	}
	var candidate *corestate.CommitCandidate
	var revision corestate.VerifiedRevision
	var linuxState *photonlinux.LinuxState
	found := false
	err := store.Update(func(tx *bolt.Tx) (bool, error) {
		_, migrated, err := migrateLegacyLinuxStateTx(tx, trustedRoot)
		if err != nil {
			return false, err
		}
		candidate, revision, linuxState, found, err = loadStateTx(tx)
		return migrated, err
	})
	if err != nil || !found {
		return nil, found, err
	}
	common, err := corestate.RestoreStore(candidate, revision, store.CommitCommon)
	if err != nil {
		return nil, false, err
	}
	return newState(store, common, linuxState), true, nil
}

// initializeStateDB atomically creates the common and Linux state
// partitions for a previously empty database. Identity validation happens in
// the public Store before this function is called; this boundary only ensures
// that a crash cannot leave one partition without the other.
func initializeStateDB(store *corestate.BoltStore, candidate *corestate.CommitCandidate, revision corestate.VerifiedRevision, linuxState *photonlinux.LinuxState) error {
	if store == nil {
		return errors.New("bbolt state store is nil")
	}
	return store.Update(func(tx *bolt.Tx) (bool, error) {
		_, _, _, found, err := corestate.LoadBoltState(tx)
		if err != nil {
			return false, err
		}
		if found || tx.Bucket([]byte(photonlinux.LinuxStateBucketName)) != nil || tx.Bucket(bucketLegacyMeta) != nil {
			return false, errors.New("daemon state is already initialized")
		}
		commonChanged, err := corestate.CommitBoltState(tx, candidate, corestate.ChangeSet{
			VerifiedRevision: revision,
			NetworkChanged:   true,
			SecurityPriority: true,
		})
		if err != nil {
			return false, err
		}
		linuxChanged, err := photonlinux.SaveLinuxStateTx(tx, linuxState)
		return commonChanged || linuxChanged, err
	})
}
