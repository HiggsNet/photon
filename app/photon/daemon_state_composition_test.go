package main

import (
	"context"
	"errors"
	"testing"
	"time"

	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func newDaemonStateStoreTestFixture(t *testing.T, commit corestate.CommitFunc) (*DaemonStateStore, zone.ZonePath) {
	t.Helper()
	rt, managed := buildIPAMTestRuntime(t)
	view, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews: %v", err)
	}
	common := corestate.NewStoreWithCheckpoint(view.State, view.Gossip, commit)
	store, err := newDaemonStateStore(common, &linuxRuntimeState{
		EndpointACLs: map[string]endpointACL{"admin": {Name: "admin"}},
	}, nil)
	if err != nil {
		t.Fatalf("NewDaemonStateStore: %v", err)
	}
	return store, zone.ZonePath(managed)
}

func TestComposedDaemonStateStoreSerializesCommonIntentWithoutChangingRuntime(t *testing.T) {
	store, managed := newDaemonStateStoreTestFixture(t, nil)
	now := time.Unix(1000, 0)
	intent := corestate.PutRecordIntent{Zone: managed, Key: "apps/composed", Type: "application.test", Value: []byte("value")}

	preview, err := store.ApplyCommonLocalIntent(context.Background(), intent, true, now)
	if err != nil {
		t.Fatalf("ApplyCommonLocalIntent(preview): %v", err)
	}
	if preview.Committed || store.Meta().Revision != 0 {
		t.Fatalf("preview/meta = %+v/%+v", preview, store.Meta())
	}
	before := store.common.ReadView()
	if _, ok := before.State.Network.Zones[managed].Records["apps/composed"]; ok {
		t.Fatal("preview appeared in composed read view")
	}

	result, err := store.ApplyCommonLocalIntent(context.Background(), intent, false, now)
	if err != nil {
		t.Fatalf("ApplyCommonLocalIntent(commit): %v", err)
	}
	if !result.Committed || result.Record == nil || result.Record.Version != 1 || store.Meta().Revision != 1 {
		t.Fatalf("commit/meta = %+v/%+v", result, store.Meta())
	}
	after, runtime := store.readCommonAndRuntime()
	if after.State.Network.Zones[managed].Records["apps/composed"] == nil {
		t.Fatal("committed record missing from common owner")
	}
	if runtime.EndpointACLs["admin"].Name != "admin" {
		t.Fatal("common refresh discarded Linux runtime state")
	}
}

func TestComposedDaemonStateStorePersistenceFailureDoesNotRefresh(t *testing.T) {
	wantErr := errors.New("persist failed")
	store, managed := newDaemonStateStoreTestFixture(t, func(context.Context, *corestate.CommitCandidate, corestate.ChangeSet) error {
		return wantErr
	})
	_, err := store.ApplyCommonLocalIntent(context.Background(), corestate.PutRecordIntent{
		Zone: managed, Key: "apps/rejected", Type: "application.test", Value: []byte("value"),
	}, false, time.Unix(1000, 0))
	if !errors.Is(err, wantErr) {
		t.Fatalf("ApplyCommonLocalIntent error = %v", err)
	}
	after := store.common.ReadView()
	if store.Meta().Revision != 0 || after.State.Network.Zones[managed].Records["apps/rejected"] != nil {
		t.Fatalf("failed persistence changed common owner: revision=%d", store.Meta().Revision)
	}
}

func TestComposedDaemonStateStoreCheckpointRefreshDoesNotAdvanceVerifiedRevision(t *testing.T) {
	store, _ := newDaemonStateStoreTestFixture(t, nil)
	result, err := store.common.UpdatePeerCheckpoint(context.Background(), "peer.catofes.", corestate.PeerCheckpointPatch{
		BackoffUntilUnix: corestate.PatchField[int64]{Set: true, Value: 42},
	})
	if err != nil {
		t.Fatalf("UpdatePeerCheckpoint: %v", err)
	}
	if !result.Committed || result.Changes.VerifiedRevision != 0 || store.Meta().Revision != 0 {
		t.Fatalf("checkpoint result/meta = %+v/%+v", result, store.Meta())
	}
	view := store.common.ReadView()
	if got := view.Gossip.Peers["peer.catofes."].BackoffUntilUnix; got != 42 {
		t.Fatalf("checkpoint backoff = %d", got)
	}
}

func TestComposedDaemonStateStoreRuntimeCommitOrderingNoopAndStale(t *testing.T) {
	store, _ := newDaemonStateStoreTestFixture(t, nil)
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
	_, after := store.readCommonAndRuntime()
	if after.EndpointACLs["api"].Name != "api" || store.Meta().Revision != 0 {
		t.Fatalf("published runtime/meta = %+v/%+v", after.EndpointACLs, store.Meta())
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
	store, _ := newDaemonStateStoreTestFixture(t, nil)
	wantErr := errors.New("runtime persist failed")
	store.commitRuntime = func(corestate.VerifiedRevision, *linuxRuntimeState) error { return wantErr }
	_, committed, err := store.commitEndpointACLsIfRevision(0, map[string]endpointACL{"blocked": {Name: "blocked"}})
	if !errors.Is(err, wantErr) || committed {
		t.Fatalf("runtime failure = committed %v err %v", committed, err)
	}
	_, after := store.readCommonAndRuntime()
	if _, ok := after.EndpointACLs["blocked"]; ok {
		t.Fatal("failed runtime persistence published candidate")
	}
}
