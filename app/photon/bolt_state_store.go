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
	boltStore, startup, err := openLinuxDaemonState(rt)
	if err != nil {
		return corestate.LocalIntentResult{}, err
	}
	defer boltStore.Close()
	defer startup.Common.Close()
	if dryRun {
		return startup.Common.PreviewLocalIntent(intent, rt.Now())
	}
	return startup.Common.ApplyLocalIntent(context.Background(), intent, rt.Now())
}

// loadOfflineOwnerViews runs the same one-way schema migration as daemon
// startup, then closes the shared Bolt handle and returns detached snapshots
// of the two persisted owners. This is only the fallback for an unavailable
// daemon or an explicit direct operation; online readers use command-oriented
// control views and never contend for the daemon's Bolt handle.
func loadOfflineOwnerViews(rt *AppContext) (corestate.View, *linuxRuntimeState, error) {
	boltStore, startup, err := openLinuxDaemonState(rt)
	if err != nil {
		return corestate.View{}, nil, err
	}
	view := startup.Common.ReadView()
	runtime := photonlinux.CloneRuntimeState(startup.Runtime)
	startup.Common.Close()
	boltCloseErr := boltStore.Close()
	if boltCloseErr != nil {
		return corestate.View{}, nil, boltCloseErr
	}
	return view, runtime, nil
}

const daemonBoltLockTimeout = time.Second

// linuxStateSnapshot is the complete persisted input needed to start the
// Linux runtime. Candidate owns the cross-platform trusted/checkpoint state;
// Runtime owns only Linux controller and configuration fields.
type linuxStateSnapshot struct {
	Candidate       *corestate.CommitCandidate
	Revision        corestate.VerifiedRevision
	Runtime         *linuxRuntimeState
	CommonReport    corestate.BoltLoadReport
	MigrationReport legacyStateMigrationReport
	Migrated        bool
}

// linuxStartupState is the final ownership split used by the Linux process:
// Common owns verified facts and gossip restart hints, while Runtime contains
// only Linux controller/configuration state. Both persist through the same
// process-wide BoltStore handle.
type linuxStartupState struct {
	Common          *corestate.Store
	Runtime         *linuxRuntimeState
	CommonReport    corestate.BoltLoadReport
	MigrationReport legacyStateMigrationReport
	Migrated        bool
}

func openLinuxDaemonState(rt *AppContext) (*corestate.BoltStore, linuxStartupState, error) {
	var startup linuxStartupState
	if rt == nil || rt.Config == nil || rt.StatePath == "" {
		return nil, startup, errors.New("daemon runtime state path is not configured")
	}
	store, err := corestate.OpenBoltStore(rt.StatePath, 0o600, daemonBoltLockTimeout)
	if err != nil {
		return nil, startup, err
	}
	startup, found, err := loadAndRestoreLinuxState(store, rt.Config.TrustedRootPublicKey)
	if err != nil {
		_ = store.Close()
		return nil, linuxStartupState{}, err
	}
	if !found {
		// Only an uninitialized database may enter the pending identity bootstrap
		// path. Existing legacy databases were already migrated by the first call.
		// The bootstrap writer initializes the current common/Linux partitions with
		// an authority-less managed-zone placeholder; no temporary legacy schema is
		// created for a new node.
		if err := store.Close(); err != nil {
			return nil, linuxStartupState{}, err
		}
		if err := writeConfiguredPendingBootstrap(rt.StatePath, rt.Config); err != nil {
			return nil, linuxStartupState{}, err
		}
		store, err = corestate.OpenBoltStore(rt.StatePath, 0o600, daemonBoltLockTimeout)
		if err != nil {
			return nil, linuxStartupState{}, err
		}
		startup, found, err = loadAndRestoreLinuxState(store, rt.Config.TrustedRootPublicKey)
		if err != nil || !found {
			_ = store.Close()
			if err != nil {
				return nil, linuxStartupState{}, err
			}
			return nil, linuxStartupState{}, errors.New("daemon state is not initialized")
		}
	}
	if err := validateConfiguredIdentityState(startup.Common.ReadView().State, rt.Config); err != nil {
		startup.Common.Close()
		_ = store.Close()
		return nil, linuxStartupState{}, err
	}
	return store, startup, nil
}

// loadAndMigrateLinuxState composes the common and Linux bucket codecs through
// the process-wide BoltStore. It does not own or expose another DB handle.
func loadAndMigrateLinuxState(store *corestate.BoltStore, trustedRoot ed25519.PublicKey) (linuxStateSnapshot, bool, error) {
	var snapshot linuxStateSnapshot
	if store == nil {
		return snapshot, false, errors.New("bbolt state store is nil")
	}
	found := false
	err := store.Update(func(tx *bolt.Tx) (bool, error) {
		migrationReport, migrated, err := migrateLegacyRuntimeStateTx(tx, trustedRoot)
		if err != nil {
			return false, err
		}
		loaded, commonFound, err := loadLinuxStateTx(tx)
		if err != nil {
			return false, err
		}
		if !commonFound {
			return migrated, nil
		}
		snapshot = loaded
		snapshot.MigrationReport = migrationReport
		snapshot.Migrated = migrated
		found = true
		return migrated, nil
	})
	return snapshot, found, err
}

func loadLinuxStateTx(tx *bolt.Tx) (linuxStateSnapshot, bool, error) {
	candidate, revision, commonReport, found, err := corestate.LoadBoltState(tx)
	if err != nil || !found {
		return linuxStateSnapshot{}, found, err
	}
	runtimeState, runtimeFound, err := photonlinux.LoadRuntimeStateTx(tx)
	if err != nil {
		return linuxStateSnapshot{}, false, err
	}
	if !runtimeFound {
		return linuxStateSnapshot{}, false, fmt.Errorf("%w: runtime bucket is missing", photonlinux.ErrRuntimeStateCorrupt)
	}
	return linuxStateSnapshot{
		Candidate:    candidate,
		Revision:     revision,
		Runtime:      runtimeState,
		CommonReport: commonReport,
	}, true, nil
}

// loadAndRestoreLinuxState performs the complete persistent startup boundary:
// it upgrades a legacy database when necessary, loads both logical partitions
// through one BoltStore transaction, and restores the common in-memory Store
// with the persisted verified revision. The returned Store commits directly
// through the same BoltStore owner.
//
// The online daemon uses this as its sole startup path; verified, checkpoint
// and Linux runtime writes all return through the same BoltStore owner.
func loadAndRestoreLinuxState(store *corestate.BoltStore, trustedRoot ed25519.PublicKey) (linuxStartupState, bool, error) {
	var startup linuxStartupState
	snapshot, found, err := loadAndMigrateLinuxState(store, trustedRoot)
	if err != nil || !found {
		return startup, found, err
	}
	common, err := corestate.RestoreStore(snapshot.Candidate, snapshot.Revision, store.CommitCommon)
	if err != nil {
		return startup, false, err
	}
	startup = linuxStartupState{
		Common:          common,
		Runtime:         snapshot.Runtime,
		CommonReport:    snapshot.CommonReport,
		MigrationReport: snapshot.MigrationReport,
		Migrated:        snapshot.Migrated,
	}
	return startup, true, nil
}

// initializeLinuxState atomically creates the common and Linux runtime
// partitions for a previously empty database. Identity validation happens in
// the public Store before this function is called; this boundary only ensures
// that a crash cannot leave one partition without the other.
func initializeLinuxState(store *corestate.BoltStore, candidate *corestate.CommitCandidate, revision corestate.VerifiedRevision, runtimeState *linuxRuntimeState) error {
	if store == nil {
		return errors.New("bbolt state store is nil")
	}
	return store.Update(func(tx *bolt.Tx) (bool, error) {
		_, _, _, found, err := corestate.LoadBoltState(tx)
		if err != nil {
			return false, err
		}
		if found || tx.Bucket([]byte(photonlinux.RuntimeStateBucketName)) != nil || tx.Bucket(bucketLegacyMeta) != nil {
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
		runtimeChanged, err := photonlinux.SaveRuntimeStateTx(tx, runtimeState)
		return commonChanged || runtimeChanged, err
	})
}
