package host

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

type memoryGossipController struct {
	trace  []string
	issues []GossipExecutionIssue
}

func gossipConfigCapturingIssues(config GossipDriverConfig, issues *[]GossipExecutionIssue) GossipDriverConfig {
	config.Log = func(event GossipDriverLog) {
		if event.Err != nil {
			*issues = append(*issues, GossipExecutionIssue{Phase: event.Phase, PeerID: event.PeerID, Err: event.Err})
		}
	}
	return config
}

// These adapters intentionally add no behavior: their only purpose is to
// prove that platform composition selects capabilities, not an executor.
type memoryLinuxGossipController struct{ memoryGossipController }
type memoryWindowsGossipController struct{ memoryGossipController }

type memoryGossipStateStore struct {
	views       []corestate.View
	trace       *[]string
	applyResult corestate.RemoteBatchResult
	applyErr    error
	batch       []corestate.RemoteSnapshot
	appliedAt   time.Time
	updates     []map[string]corestate.PeerCheckpointPatch
	updateErr   error
}

func (reader *memoryGossipStateStore) UpdatePeerCheckpoints(_ context.Context, patches map[string]corestate.PeerCheckpointPatch) (corestate.CommitResult, error) {
	if reader.trace != nil {
		*reader.trace = append(*reader.trace, "checkpoint")
	}
	reader.updates = append(reader.updates, patches)
	return corestate.CommitResult{Committed: reader.updateErr == nil}, reader.updateErr
}

func (reader *memoryGossipStateStore) ApplyRemoteBatch(_ context.Context, _ string, batch []corestate.RemoteSnapshot, now time.Time) (corestate.RemoteBatchResult, error) {
	if reader.trace != nil {
		*reader.trace = append(*reader.trace, "apply")
	}
	reader.batch = append([]corestate.RemoteSnapshot(nil), batch...)
	reader.appliedAt = now
	return reader.applyResult, reader.applyErr
}

func (reader *memoryGossipStateStore) ReadView() corestate.View {
	if reader == nil {
		return corestate.View{}
	}
	if reader.trace != nil {
		*reader.trace = append(*reader.trace, "read")
	}
	if len(reader.views) == 0 {
		return corestate.View{}
	}
	view := reader.views[0]
	if len(reader.views) > 1 {
		reader.views = reader.views[1:]
	}
	return view
}

func loadedGossipState(paths ...zone.ZonePath) corestate.View {
	network := zone.NewNetworkState()
	for _, path := range paths {
		network.Zones[path] = zone.NewZoneState(path, nil)
	}
	return corestate.View{State: &corestate.VerifiedState{Network: network}}
}

func loadedManagedGossipState(managed zone.ZonePath, paths ...zone.ZonePath) corestate.View {
	view := loadedGossipState(paths...)
	view.State.ManagedZone = managed
	return view
}

type successfulObjectPullClient struct {
	pulls chan gossip.StartObjectPullAction
}

func (client successfulObjectPullClient) Exchange(_ context.Context, _ string, request *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	if client.pulls != nil {
		client.pulls <- gossip.StartObjectPullAction{PeerID: "peer-a", Zone: request.Zone}
	}
	return &gossip.ObjectPullResponse{OK: true, Snapshot: &corestate.ZoneSnapshot{Zone: request.Zone}}, nil
}

func memoryObjectPullExecutor(pulls chan gossip.StartObjectPullAction) *GossipObjectPullExecutor {
	return NewGossipObjectPullExecutor(GossipObjectPullExecutorConfig{
		Client: successfulObjectPullClient{pulls: pulls},
		Discovery: func() GossipDiscoveryInput {
			return GossipDiscoveryInput{
				Network:   zone.NewNetworkState(),
				Bootstrap: map[string]*net.UDPAddr{"peer-a": {IP: net.ParseIP("127.0.0.1"), Port: 1}},
			}
		},
	})
}

func (controller *memoryGossipController) SendGossip(_ context.Context, outbound gossip.OutboundMessage) error {
	controller.trace = append(controller.trace, "send:"+string(outbound.Message.Type))
	return nil
}

func TestGossipDriverExecuteGossipActionsUsesCommonOrdering(t *testing.T) {
	clock := newFakeClock(time.Unix(100, 0))
	controller := &memoryGossipController{}
	state := &memoryGossipStateStore{
		views:       []corestate.View{loadedGossipState(), loadedGossipState(), loadedGossipState("node-a.catofes.")},
		trace:       &controller.trace,
		applyResult: corestate.RemoteBatchResult{CommitResult: corestate.CommitResult{Committed: true, Changes: corestate.ChangeSet{NetworkChanged: true}}, Outcomes: []corestate.RemoteApplyOutcome{{Zone: "node-a.catofes.", Result: &corestate.ApplyResult{NetworkChanged: true}}}},
	}
	driver := NewGossipDriver(clock, 4, state, GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer driver.Stop()
	pulls := make(chan gossip.StartObjectPullAction, 1)
	if err := driver.StartGossipObjectPullWorkers(t.Context(), memoryObjectPullExecutor(pulls), 1, 1); err != nil {
		t.Fatal(err)
	}
	session := &gossip.SyncSession{PeerID: "peer-a", State: gossip.SyncSessionCompleted}
	deadline := clock.Now().Add(time.Second)
	actions := []gossip.SyncAction{
		gossip.StartObjectPullAction{PeerID: "peer-a", Zone: "node-a.catofes."},
		gossip.SendPingAction{PeerID: "peer-a"},
		gossip.ApplySnapshotAction{PeerID: "peer-a", Snapshot: &corestate.ZoneSnapshot{Zone: "node-a.catofes."}},
		gossip.StartTimerAction{PeerID: "peer-a", Kind: gossip.TimerKindRound, Deadline: deadline},
		gossip.RecordBackoffAction{PeerID: "peer-a", Err: errors.New("retry")},
	}

	result := driver.ExecuteGossipActions(context.Background(), session, actions, controller)
	if result.Aborted || !result.NetworkChanged {
		t.Fatalf("result = %#v", result)
	}
	wantTrace := []string{"read", "apply", "read", "send:ping", "read", "checkpoint"}
	if !slices.Equal(controller.trace, wantTrace) {
		t.Fatalf("trace = %#v, want %#v", controller.trace, wantTrace)
	}
	if len(state.updates) != 1 {
		t.Fatalf("checkpoint updates = %#v", state.updates)
	}
	patch := state.updates[0]["peer-a"]
	if !patch.LastSyncUnix.Set || patch.LastSyncUnix.Value != clock.Now().Unix() || patch.BackoffUntilUnix.Value != 0 || patch.LastFailure.Value != nil {
		t.Fatalf("terminal checkpoint patch = %#v", patch)
	}
	if pull := <-pulls; pull.PeerID != "peer-a" || pull.Zone != "node-a.catofes." {
		t.Fatalf("pull = %#v", pull)
	}
	if event, ok := driver.GossipSessionEventFor(<-driver.Events()); !ok {
		t.Fatal("object-pull completion was not queued")
	} else if _, ok := event.(*gossip.ObjectPullResultEvent); !ok {
		t.Fatalf("event = %T, want *gossip.ObjectPullResultEvent", event)
	}
	clock.Advance(time.Second)
	if fired := receiveTimer(t, driver.Events()); fired.ID.Owner != "peer-a" || fired.ID.Key != gossip.TimerKindRound {
		t.Fatalf("timer = %#v", fired)
	}
}

func TestGossipDriverExecuteGossipActionsApplyFailureStopsLaterPhases(t *testing.T) {
	applyErr := errors.New("commit failed")
	controller := &memoryGossipController{}
	driver := NewGossipDriver(newFakeClock(time.Unix(100, 0)), 1, &memoryGossipStateStore{views: []corestate.View{loadedGossipState(), loadedGossipState()}, trace: &controller.trace, applyErr: applyErr}, gossipConfigCapturingIssues(GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()}, &controller.issues))
	defer driver.Stop()
	session := &gossip.SyncSession{PeerID: "peer-a", State: gossip.SyncSessionObjectPulling}
	result := driver.ExecuteGossipActions(context.Background(), session, []gossip.SyncAction{
		gossip.ApplySnapshotAction{PeerID: "peer-a", Snapshot: &corestate.ZoneSnapshot{Zone: "node-a.catofes."}},
		gossip.SendPingAction{PeerID: "peer-a"},
	}, controller)
	if !result.Aborted || result.NetworkChanged {
		t.Fatalf("result = %#v", result)
	}
	if want := []string{"read", "apply"}; !slices.Equal(controller.trace, want) {
		t.Fatalf("trace = %#v, want %#v", controller.trace, want)
	}
	if len(controller.issues) != 1 || controller.issues[0].Phase != GossipPhaseApply || !errors.Is(controller.issues[0].Err, applyErr) {
		t.Fatalf("issues = %#v", controller.issues)
	}
}

func TestGossipDriverApplySnapshotsOwnsStoreTransactionAndCompletion(t *testing.T) {
	now := time.Unix(100, 0)
	clock := newFakeClock(now)
	controller := &memoryGossipController{}
	state := &memoryGossipStateStore{
		views: []corestate.View{
			loadedManagedGossipState("local.catofes.", "local.catofes."),
			loadedManagedGossipState("local.catofes.", "local.catofes.", "remote.catofes."),
		},
		applyResult: corestate.RemoteBatchResult{
			CommitResult: corestate.CommitResult{Committed: true, Changes: corestate.ChangeSet{NetworkChanged: true}},
			Outcomes:     []corestate.RemoteApplyOutcome{{Zone: "remote.catofes.", Result: &corestate.ApplyResult{NetworkChanged: true}}},
		},
	}
	driver := NewGossipDriver(clock, 2, state, GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer driver.Stop()
	result := driver.ExecuteGossipActions(context.Background(), &gossip.SyncSession{PeerID: "peer-a"}, []gossip.SyncAction{
		gossip.ApplySnapshotAction{PeerID: "peer-a", Snapshot: &corestate.ZoneSnapshot{Zone: "local.catofes."}},
		gossip.ApplySnapshotAction{PeerID: "peer-a", Snapshot: &corestate.ZoneSnapshot{Zone: "remote.catofes."}, RelaxedLimits: true, ReportResult: true},
	}, controller)
	if result.Aborted || !result.NetworkChanged {
		t.Fatalf("result = %#v", result)
	}
	if len(state.batch) != 1 || state.batch[0].Snapshot.Zone != "remote.catofes." || state.batch[0].Limits.MaxBytes != 8<<20 || !state.appliedAt.Equal(now) {
		t.Fatalf("batch/time = %#v/%v", state.batch, state.appliedAt)
	}
	event, ok := driver.GossipSessionEventFor(<-driver.Events())
	if !ok {
		t.Fatal("snapshot completion was not queued")
	}
	applied, ok := event.(*gossip.SnapshotAppliedEvent)
	if !ok || applied.Zone != "remote.catofes." || applied.Err != nil {
		t.Fatalf("completion = %#v", event)
	}
}

func TestGossipDriverExecuteGossipActionsMemoryAdaptersAreEquivalent(t *testing.T) {
	actions := []gossip.SyncAction{
		gossip.SendFetchCatalogPageAction{PeerID: "peer-a", Cursor: "2"},
		gossip.StartObjectPullAction{PeerID: "peer-a", Zone: "node-a.catofes."},
	}
	type outcome struct {
		trace   []string
		failure []string
		issue   GossipExecutionIssue
	}
	adapters := []struct {
		name string
		new  func() (GossipSender, *memoryGossipController)
	}{
		{
			name: "linux",
			new: func() (GossipSender, *memoryGossipController) {
				controller := &memoryLinuxGossipController{}
				return controller, &controller.memoryGossipController
			},
		},
		{
			name: "windows",
			new: func() (GossipSender, *memoryGossipController) {
				controller := &memoryWindowsGossipController{}
				return controller, &controller.memoryGossipController
			},
		},
	}
	var outcomes []outcome
	commitErr := errors.New("commit failed")
	for _, adapter := range adapters {
		controller, memory := adapter.new()
		driver := NewGossipDriver(newFakeClock(time.Unix(100, 0)), 1, &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}, trace: &memory.trace}, GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
		if err := driver.StartGossipObjectPullWorkers(t.Context(), memoryObjectPullExecutor(nil), 1, 1); err != nil {
			t.Fatal(err)
		}
		driver.ExecuteGossipActions(context.Background(), &gossip.SyncSession{PeerID: "peer-a"}, actions, controller)
		driver.Stop()

		failureController, failureMemory := adapter.new()
		failureDriver := NewGossipDriver(newFakeClock(time.Unix(100, 0)), 1, &memoryGossipStateStore{views: []corestate.View{loadedGossipState(), loadedGossipState()}, trace: &failureMemory.trace, applyErr: commitErr}, gossipConfigCapturingIssues(GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()}, &failureMemory.issues))
		failureDriver.ExecuteGossipActions(context.Background(), &gossip.SyncSession{PeerID: "peer-a"}, []gossip.SyncAction{
			gossip.ApplySnapshotAction{PeerID: "peer-a", Snapshot: &corestate.ZoneSnapshot{Zone: "node-a.catofes."}},
			gossip.SendPingAction{PeerID: "peer-a"},
		}, failureController)
		failureDriver.Stop()
		if len(failureMemory.issues) != 1 {
			t.Fatalf("%s issues = %#v, want one", adapter.name, failureMemory.issues)
		}
		outcomes = append(outcomes, outcome{
			trace:   append([]string(nil), memory.trace...),
			failure: append([]string(nil), failureMemory.trace...),
			issue:   failureMemory.issues[0],
		})
	}
	left, right := outcomes[0], outcomes[1]
	if !slices.Equal(left.trace, right.trace) ||
		!slices.Equal(left.failure, right.failure) ||
		left.issue.Phase != right.issue.Phase ||
		left.issue.PeerID != right.issue.PeerID ||
		!errors.Is(left.issue.Err, right.issue.Err) {
		t.Fatalf("adapter outcomes differ: %#v", outcomes)
	}
	if want := []string{"read", "send:fetch_catalog_page"}; !slices.Equal(outcomes[0].trace, want) {
		t.Fatalf("trace = %#v, want %#v", outcomes[0].trace, want)
	}
	if want := []string{"read", "apply"}; !slices.Equal(outcomes[0].failure, want) || outcomes[0].issue.Phase != GossipPhaseApply {
		t.Fatalf("failure outcome = %#v", outcomes[0])
	}
}
