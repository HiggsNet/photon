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

type countingCheckpointStore struct {
	GossipStateStore
	updates int
}

func (store *countingCheckpointStore) UpdatePeerCheckpoints(ctx context.Context, patches map[string]corestate.PeerCheckpointPatch) (corestate.CommitResult, error) {
	store.updates++
	return store.GossipStateStore.UpdatePeerCheckpoints(ctx, patches)
}

func TestMatchingPingBurstSkipsAlreadyCommittedCompletion(t *testing.T) {
	now := time.Unix(1000, 0)
	commits := 0
	common := corestate.NewStoreWithCheckpoint(
		&corestate.VerifiedState{ManagedZone: "local.catofes.", Network: zone.NewNetworkState()},
		&corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{"peer-a": {
			ObservedEndpoint: "127.0.0.1:33434", ObservedUntilUnix: now.Add(time.Minute).Unix(), ObservedFailureCount: 2,
		}}}, nil,
		func(context.Context, map[string]*corestate.PeerCheckpoint, corestate.VerifiedRevision) error {
			commits++
			return nil
		},
	)
	store := &countingCheckpointStore{GossipStateStore: common}
	clock := newFakeClock(now)
	driver := NewGossipDriver(clock, 64, store, GossipDriverConfig{PeerID: "local.catofes."})
	defer driver.Stop()
	bindMemoryGossipTransport(t, driver, "peer-a")
	summary := driver.GossipCatalogSummary()
	session := driver.Gossip.NewSession("peer-a")
	_, _ = session.OnEvent(&gossip.SyncTimerEvent{PeerID: "peer-a", LocalSummary: summary}, now)
	packet := GossipPacketReceived{Packet: &gossip.Packet{Message: &gossip.Message{PeerID: "peer-a", Type: gossip.MessagePing, Ping: &gossip.Ping{Summary: summary}}}}
	for range 20 {
		driver.events <- packet
	}
	for driver.PendingEventCount() > 0 {
		if _, err := driver.HandleGossipHostEvent(t.Context(), <-driver.Events(), now, nil); err != nil {
			t.Fatal(err)
		}
	}
	if store.updates != 1 || commits != 1 {
		t.Fatalf("updates=%d persisted commits=%d, want 1/1", store.updates, commits)
	}
	peer := common.PeerCheckpoints([]string{"peer-a"})["peer-a"]
	if peer.ObservedFailureCount != 0 || peer.ObservedLastSyncUnix != now.Unix() {
		t.Fatalf("completion=%+v", peer)
	}
	now = now.Add(time.Second)
	clock.Advance(time.Second)
	if _, err := driver.HandleGossipHostEvent(t.Context(), packet, now, nil); err != nil {
		t.Fatal(err)
	}
	if store.updates != 2 || commits != 2 {
		t.Fatalf("new second updates=%d commits=%d, want 2/2", store.updates, commits)
	}
	// A same-second failure must still be cleared, even though LastSyncUnix
	// already matches. Coalescing is based on the actual checkpoint fields.
	if _, err := common.UpdatePeerCheckpoints(t.Context(), map[string]corestate.PeerCheckpointPatch{"peer-a": {
		FailureCount:     corestate.PatchField[int]{Set: true, Value: 3},
		ObservedFailures: corestate.PatchField[int]{Set: true, Value: 2},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.HandleGossipHostEvent(t.Context(), packet, now, nil); err != nil {
		t.Fatal(err)
	}
	peer = common.PeerCheckpoints([]string{"peer-a"})["peer-a"]
	if store.updates != 3 || peer.FailureCount != 0 || peer.ObservedFailureCount != 0 {
		t.Fatalf("updates=%d recovered=%+v", store.updates, peer)
	}
}

func TestCompletionRetryAfterPersistenceFailureIsNotCoalesced(t *testing.T) {
	now := time.Unix(1000, 0)
	wantErr := errors.New("checkpoint write failed")
	attempts := 0
	common := corestate.NewStore(&corestate.VerifiedState{ManagedZone: "local.catofes.", Network: zone.NewNetworkState()}, nil,
		func(context.Context, map[string]*corestate.PeerCheckpoint, corestate.VerifiedRevision) error {
			attempts++
			if attempts == 1 {
				return wantErr
			}
			return nil
		})
	driver := NewGossipDriver(newFakeClock(now), 4, common, GossipDriverConfig{})
	defer driver.Stop()
	session := &gossip.SyncSession{PeerID: "peer-a", State: gossip.SyncSessionCompleted}
	if err := driver.commitGossipEventCheckpoint(t.Context(), session, nil, now); !errors.Is(err, wantErr) {
		t.Fatalf("first commit=%v", err)
	}
	if err := driver.commitGossipEventCheckpoint(t.Context(), session, nil, now); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || common.PeerCheckpoints([]string{"peer-a"})["peer-a"].LastSyncUnix != now.Unix() {
		t.Fatal("uncommitted completion was suppressed")
	}
}

func TestGossipDriverCommitsBackoffAndCompletionOnceWithoutAdvancingRevision(t *testing.T) {
	now := time.Unix(100, 0)
	commits := 0
	var committed map[string]*corestate.PeerCheckpoint
	store := corestate.NewStoreWithCheckpoint(
		&corestate.VerifiedState{ManagedZone: "local.catofes.", Network: zone.NewNetworkState()},
		&corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{"peer-a": {ObservedEndpoint: "127.0.0.1:33434", ObservedUntilUnix: now.Add(time.Minute).Unix(), ObservedFailureCount: 2}}},
		nil, func(_ context.Context, candidate map[string]*corestate.PeerCheckpoint, revision corestate.VerifiedRevision) error {
			commits++
			committed = candidate
			if revision != 0 {
				t.Fatalf("checkpoint revision = %d", revision)
			}
			return nil
		},
	)
	driver := NewGossipDriver(newFakeClock(now), 2, store, GossipDriverConfig{PeerID: "local.catofes."})
	defer driver.Stop()
	session := driver.Gossip.NewSession("peer-a")
	session.State = gossip.SyncSessionSummarySent
	controller := &memoryGossipController{}

	result, _, err := driver.handleGossipSessionEvent(context.Background(), &gossip.RoundTimeoutEvent{PeerID: "peer-a"}, now, controller)
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
