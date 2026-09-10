package main

import (
	"context"
	"errors"
	"testing"

	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func newDaemonStateStoreTestFixture(t *testing.T) *DaemonStateStore {
	t.Helper()
	rt, _ := buildIPAMTestRuntime(t)
	view, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews: %v", err)
	}
	common := corestate.NewStoreWithCheckpoint(view.State, view.Gossip, nil)
	store, err := newDaemonStateStore(common, &linuxRuntimeState{
		EndpointACLs: map[string]endpointACL{"admin": {Name: "admin"}},
	}, nil)
	if err != nil {
		t.Fatalf("NewDaemonStateStore: %v", err)
	}
	return store
}

func TestComposedDaemonStateStoreCheckpointRefreshDoesNotAdvanceVerifiedRevision(t *testing.T) {
	store := newDaemonStateStoreTestFixture(t)
	result, err := store.common.UpdatePeerCheckpoint(context.Background(), "peer.catofes.", corestate.PeerCheckpointPatch{
		BackoffUntilUnix: corestate.PatchField[int64]{Set: true, Value: 42},
	})
	if err != nil {
		t.Fatalf("UpdatePeerCheckpoint: %v", err)
	}
	if !result.Committed || result.Changes.VerifiedRevision != 0 || uint64(store.common.VerifiedRevision()) != 0 {
		t.Fatalf("checkpoint result/revision = %+v/%d", result, store.common.VerifiedRevision())
	}
	view := store.common.ReadView()
	if got := view.Gossip.Peers["peer.catofes."].BackoffUntilUnix; got != 42 {
		t.Fatalf("checkpoint backoff = %d", got)
	}
}

func TestComposedDaemonStateStoreRuntimeCommitOrderingNoopAndStale(t *testing.T) {
	store := newDaemonStateStoreTestFixture(t)
	commits := 0
	store.commitRuntime = func(revision corestate.VerifiedRevision, candidate *linuxRuntimeState) error {
		commits++
		if revision != 0 || candidate.EndpointACLs["api"].Name != "api" {
			t.Fatalf("runtime commit candidate = revision %d, state %+v", revision, candidate.EndpointACLs)
		}
		store.mu.RLock()
		published := photonstate.CloneEndpointACLs(store.runtime.EndpointACLs)
		store.mu.RUnlock()
		if _, exists := published["api"]; exists {
			t.Fatal("runtime view published before persistence callback")
		}
		return nil
	}
	acls := map[string]endpointACL{"api": {Name: "api"}}
	if revision, committed, err := store.commitEndpointACLsIfRevision(0, acls); err != nil || !committed || revision != 0 {
		t.Fatalf("endpoint ACL runtime commit = revision %d committed %v err %v", revision, committed, err)
	}
	after := store.readLinuxState()
	if after.EndpointACLs["api"].Name != "api" || uint64(store.common.VerifiedRevision()) != 0 {
		t.Fatalf("published runtime/revision = %+v/%d", after.EndpointACLs, store.common.VerifiedRevision())
	}
	if _, committed, err := store.commitEndpointACLsIfRevision(0, acls); err != nil || committed {
		t.Fatalf("runtime no-op = committed %v err %v", committed, err)
	}
	if _, committed, err := store.commitEndpointACLsIfRevision(1, map[string]endpointACL{"stale": {Name: "stale"}}); err != nil || committed {
		t.Fatalf("stale runtime commit = committed %v err %v", committed, err)
	}
	if commits != 1 {
		t.Fatalf("runtime persistence calls = %d, want 1", commits)
	}
}

func TestComposedDaemonStateStoreRuntimePersistenceFailureDoesNotPublish(t *testing.T) {
	store := newDaemonStateStoreTestFixture(t)
	wantErr := errors.New("runtime persist failed")
	store.commitRuntime = func(corestate.VerifiedRevision, *linuxRuntimeState) error { return wantErr }
	_, committed, err := store.commitEndpointACLsIfRevision(0, map[string]endpointACL{"blocked": {Name: "blocked"}})
	if !errors.Is(err, wantErr) || committed {
		t.Fatalf("runtime failure = committed %v err %v", committed, err)
	}
	after := store.readLinuxState()
	if _, ok := after.EndpointACLs["blocked"]; ok {
		t.Fatal("failed runtime persistence published candidate")
	}
}
