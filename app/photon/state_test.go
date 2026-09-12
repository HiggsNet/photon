package main

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func newStateTestFixture(t *testing.T) *State {
	t.Helper()
	rt, _ := buildIPAMTestRuntime(t)
	view, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews: %v", err)
	}
	return newState(nil, corestate.NewStoreWithCheckpoint(view.State, view.Gossip, nil), &photonlinux.LinuxState{
		EndpointACLs: map[string]photonstate.EndpointACL{"admin": {Name: "admin"}},
	})
}

func TestStateLinuxCommitNoopAndStale(t *testing.T) {
	state := newStateTestFixture(t)

	acls := map[string]photonstate.EndpointACL{"api": {Name: "api"}}
	if committed, err := state.ReplaceEndpointACLsIfRevision(0, acls); err != nil || !committed {
		t.Fatalf("endpoint ACL Linux state commit = committed %v err %v", committed, err)
	}
	after := state.ReadLinux()
	if after.EndpointACLs["api"].Name != "api" || uint64(state.Common.VerifiedRevision()) != 0 {
		t.Fatalf("published Linux state/revision = %+v/%d", after.EndpointACLs, state.Common.VerifiedRevision())
	}
	if committed, err := state.ReplaceEndpointACLsIfRevision(0, acls); err != nil || committed {
		t.Fatalf("Linux state no-op = committed %v err %v", committed, err)
	}
	if _, err := advanceTestVerifiedRevision(state.Common, time.Unix(1, 0)); err != nil {
		t.Fatalf("advance verified revision: %v", err)
	}
	if committed, err := state.ReplaceEndpointACLsIfRevision(0, map[string]photonstate.EndpointACL{"stale": {Name: "stale"}}); !errors.Is(err, errStateRevisionStale) || committed {
		t.Fatalf("stale Linux state commit = committed %v err %v", committed, err)
	}
}

func TestStateLinuxPersistenceFailureDoesNotPublish(t *testing.T) {
	stateDB, err := corestate.OpenBoltStore(filepath.Join(t.TempDir(), "closed.db"), 0o600, time.Second)
	if err != nil {
		t.Fatalf("OpenBoltStore: %v", err)
	}
	if err := stateDB.Close(); err != nil {
		t.Fatalf("Close StateDB: %v", err)
	}

	state := newStateTestFixture(t)
	state.db = stateDB
	committed, err := state.ReplaceEndpointACLsIfRevision(0, map[string]photonstate.EndpointACL{"blocked": {Name: "blocked"}})
	if err == nil || committed {
		t.Fatalf("Linux state failure = committed %v err %v", committed, err)
	}
	if _, ok := state.ReadLinux().EndpointACLs["blocked"]; ok {
		t.Fatal("failed Linux state persistence published candidate")
	}
}
