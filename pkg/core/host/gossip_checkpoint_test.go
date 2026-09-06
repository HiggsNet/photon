package host

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestGossipDriverCommitsBackoffAndCompletionOnceWithoutAdvancingRevision(t *testing.T) {
	now := time.Unix(100, 0)
	commits := 0
	var committed *corestate.CommitCandidate
	store := corestate.NewStoreWithCheckpoint(
		&corestate.VerifiedState{ManagedZone: "local.catofes.", Network: zone.NewNetworkState()},
		&corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{"peer-a": {ObservedEndpoint: "127.0.0.1:33434", ObservedUntilUnix: now.Add(time.Minute).Unix(), ObservedFailureCount: 2}}},
		func(_ context.Context, candidate *corestate.CommitCandidate, changes corestate.ChangeSet) error {
			commits++
			committed = candidate
			if changes.NetworkChanged || !changes.GossipCheckpointChanged || changes.VerifiedRevision != 0 {
				t.Fatalf("checkpoint changes = %#v", changes)
			}
			return nil
		},
	)
	driver := NewGossipDriver(newFakeClock(now), 2, store, GossipDriverConfig{PeerID: "local.catofes."})
	defer driver.Stop()
	session := driver.Gossip.NewSession("peer-a")
	session.State = gossip.SyncSessionSummarySent
	controller := &memoryGossipController{}

	result, err := driver.handleGossipSessionEvent(context.Background(), &gossip.RoundTimeoutEvent{PeerID: "peer-a"}, now, controller)
	if err != nil || !result.Done || result.NewState != gossip.SyncSessionFailed {
		t.Fatalf("result/error = %#v/%v", result, err)
	}
	if commits != 1 || committed == nil {
		t.Fatalf("checkpoint commits = %d candidate=%#v", commits, committed)
	}
	peer := store.ReadView().Gossip.Peers["peer-a"]
	if peer.FailureCount != 1 || peer.LastAttemptUnix != now.Unix() || peer.BackoffUntilUnix != now.Add(2*time.Second).Unix() {
		t.Fatalf("failed completion checkpoint = %#v", peer)
	}
	if peer.LastFailure == nil || peer.LastFailure.Message == "" || peer.ObservedFailureCount != 2 {
		t.Fatalf("failure details = %#v", peer)
	}
	if store.VerifiedRevision() != 0 {
		t.Fatalf("verified revision = %d, want 0", store.VerifiedRevision())
	}
}

func TestGossipDriverReportsCheckpointCommitFailure(t *testing.T) {
	wantErr := errors.New("checkpoint commit failed")
	state := &memoryGossipStateStore{
		views:     []corestate.View{loadedGossipState(), loadedGossipState()},
		updateErr: wantErr,
	}
	controller := &memoryGossipController{}
	driver := NewGossipDriver(newFakeClock(time.Unix(100, 0)), 1, state, gossipConfigCapturingIssues(GossipDriverConfig{}, &controller.issues))
	defer driver.Stop()
	session := &gossip.SyncSession{PeerID: "peer-a", State: gossip.SyncSessionCompleted}

	result := driver.ExecuteGossipActions(context.Background(), session, nil, controller)
	if result.Aborted || len(controller.issues) != 1 || controller.issues[0].Phase != GossipPhasePersistence || !errors.Is(controller.issues[0].Err, wantErr) {
		t.Fatalf("result/issues = %#v/%#v", result, controller.issues)
	}
}
