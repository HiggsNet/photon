package main

import (
	"fmt"
	"testing"

	"github.com/HiggsNet/photon/internal/photonlinux"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func loadConfiguredVerifiedState() (*corestate.VerifiedState, error) {
	runtime, err := NewAppContext()
	if err != nil {
		return nil, err
	}
	common, _, err := loadOfflineOwnerViews(runtime)
	if err != nil {
		return nil, err
	}
	if common.State == nil {
		return nil, fmt.Errorf("configured state has no verified owner")
	}
	return common.State, nil
}

// seedPartitionedStateDB initializes an empty current-schema database and
// closes it so an offline command can reopen the file through production code.
func seedPartitionedStateDB(
	t *testing.T,
	path string,
	verified *corestate.VerifiedState,
	checkpoint *corestate.GossipCheckpoint,
	linuxState *photonlinux.LinuxState,
) {
	t.Helper()
	store, err := corestate.OpenBoltStore(path, 0o600, daemonBoltLockTimeout)
	if err != nil {
		t.Fatalf("OpenBoltStore: %v", err)
	}
	if err := initializeStateDB(store, &corestate.CommitCandidate{
		Verified: verified,
		Gossip:   checkpoint,
	}, 0, linuxState); err != nil {
		_ = store.Close()
		t.Fatalf("initializeStateDB: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close BoltStore: %v", err)
	}
}
