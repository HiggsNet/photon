package host

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strings"
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

type capturedGossipLog struct {
	Level  string
	Event  string
	PeerID string
	Phase  string
	Err    error
	Fields map[string]any
}

type gossipLogCapture func(capturedGossipLog)

func (gossipLogCapture) Enabled(context.Context, slog.Level) bool { return true }

func (capture gossipLogCapture) Handle(_ context.Context, record slog.Record) error {
	fields := make(map[string]any, record.NumAttrs())
	record.Attrs(func(attr slog.Attr) bool {
		fields[attr.Key] = attr.Value.Any()
		return true
	})
	peerID, _ := fields["peer_id"].(string)
	phase, _ := fields["phase"].(string)
	err, _ := fields["error"].(error)
	capture(capturedGossipLog{
		Level: strings.ToLower(record.Level.String()), Event: record.Message,
		PeerID: peerID, Phase: phase, Err: err, Fields: fields,
	})
	return nil
}

func gossipConfigCapturingIssues(config GossipDriverConfig, issues *[]GossipExecutionIssue) GossipDriverConfig {
	config.Log = gossipLogCapture(func(event capturedGossipLog) {
		if event.Err != nil {
			*issues = append(*issues, GossipExecutionIssue{Phase: event.Phase, PeerID: event.PeerID, Err: event.Err})
		}
	})
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

func (reader *memoryGossipStateStore) PruneRevokedPeerCheckpoints(context.Context, time.Time) error {
	return reader.updateErr
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

func (reader *memoryGossipStateStore) ReadDiscoveryRecords(peerID, prefix string) *corestate.DiscoveryView {
	return reader.readDiscovery(peerID, true, prefix)
}

func (reader *memoryGossipStateStore) ReadPeerAuthorization(peerID string) *corestate.DiscoveryView {
	return reader.readDiscovery(peerID, false, "")
}

func (reader *memoryGossipStateStore) IsZoneRevoked(path zone.ZonePath, now time.Time) bool {
	return len(reader.views) > 0 && reader.views[0].State != nil && reader.views[0].State.Network.IsZoneRevoked(path, now)
}

func (reader *memoryGossipStateStore) readDiscovery(peerID string, records bool, prefix string) *corestate.DiscoveryView {
	view := reader.ReadView()
	if view.State == nil {
		return nil
	}
	store := corestate.NewStoreWithCheckpoint(view.State, view.Gossip, nil, nil)
	var discovery *corestate.DiscoveryView
	if records {
		discovery = store.ReadDiscoveryRecords(peerID, prefix)
	} else {
		discovery = store.ReadPeerAuthorization(peerID)
	}
	if discovery != nil {
		discovery.Revision = view.Revision
	}
	return discovery
}

func (reader *memoryGossipStateStore) ReadZoneSnapshot(path zone.ZonePath, now time.Time) (*corestate.ZoneSnapshot, bool, error) {
	view := reader.ReadView()
	return corestate.NewStore(view.State, nil, nil).ReadZoneSnapshot(path, now)
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
	if event, ok := driver.GossipSessionEventFor(<-driver.Completions()); !ok {
		t.Fatal("object-pull completion was not queued")
	} else if _, ok := event.(*gossip.ObjectPullResultEvent); !ok {
		t.Fatalf("event = %T, want *gossip.ObjectPullResultEvent", event)
	}
	clock.Advance(time.Second)
	if fired := receiveTimer(t, driver.Completions()); fired.ID.Owner != "peer-a" || fired.ID.Key != gossip.TimerKindRound {
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
		gossip.ApplySnapshotAction{PeerID: "peer-a", Snapshot: &corestate.ZoneSnapshot{Zone: "remote.catofes."}, RelaxedLimits: true, ReportResult: true, RefreshOnRootMismatch: true},
	}, controller)
	if result.Aborted || !result.NetworkChanged {
		t.Fatalf("result = %#v", result)
	}
	if len(state.batch) != 1 || state.batch[0].Snapshot.Zone != "remote.catofes." || state.batch[0].Limits.MaxBytes != 8<<20 || !state.batch[0].RefreshOnRootMismatch || !state.appliedAt.Equal(now) {
		t.Fatalf("batch/time = %#v/%v", state.batch, state.appliedAt)
	}
	if len(result.Events) != 1 {
		t.Fatalf("snapshot completions = %#v", result.Events)
	}
	event := result.Events[0]
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

func (store *memoryGossipStateStore) PeerCheckpoints(ids []string) map[string]corestate.PeerCheckpoint {
	view := store.ReadView()
	out := make(map[string]corestate.PeerCheckpoint)
	if view.Gossip != nil {
		for _, id := range ids {
			if p, ok := view.Gossip.Peers[id]; ok {
				out[id] = p
			}
		}
	}
	return out
}

func (store *memoryGossipStateStore) ReadCatalog() *corestate.CatalogView {
	v := store.ReadView()
	if v.State == nil || v.State.Network == nil {
		return nil
	}
	return &corestate.CatalogView{ManagedZone: v.State.ManagedZone, Digests: corestate.ZoneDigests(v.State.Network)}
}

func TestGossipDriverCrossedPingCatalogRequests(t *testing.T) {
	for _, pingFirst := range []bool{false, true} {
		name := "pong first"
		if pingFirst {
			name = "ping first"
		}
		t.Run(name, func(t *testing.T) {
			const peer = "less."
			clock := newFakeClock(time.Unix(100, 0))
			store := &memoryGossipStateStore{views: []corestate.View{loadedGossipState("konomi.")}}
			driver := NewGossipDriver(clock, 4, store, GossipDriverConfig{PeerID: "konomi."})
			defer driver.Stop()
			sender := &memoryGossipController{}
			local := driver.GossipCatalogSummary()
			remote := &corestate.CatalogSummary{CatalogRoot: []byte("remote catalog"), ZoneCount: 32}

			deliver := func(message *gossip.Message) {
				t.Helper()
				message.PeerID = peer
				actions := driver.Gossip.PlanInbound(&gossip.Packet{Message: message})
				events, err := driver.executeGossipPacketActions(t.Context(), actions, sender, gossip.DefaultDatagramBudget)
				if err != nil {
					t.Fatal(err)
				}
				for _, event := range events {
					if _, _, err := driver.handleGossipSessionEvent(t.Context(), event, clock.Now(), sender); err != nil {
						t.Fatal(err)
					}
				}
			}
			ping := &gossip.Message{Type: gossip.MessagePing, Ping: &gossip.Ping{Summary: remote}}
			pong := &gossip.Message{Type: gossip.MessagePong, Pong: &gossip.Pong{Summary: remote}}
			driver.Gossip.NewSession(peer)
			timer := &gossip.SyncTimerEvent{PeerID: peer, LocalSummary: local}
			if _, _, err := driver.handleGossipSessionEvent(t.Context(), timer, clock.Now(), sender); err != nil {
				t.Fatal(err)
			}
			sender.trace = nil
			if pingFirst {
				deliver(ping)
				deliver(pong)
			} else {
				deliver(pong)
				deliver(ping)
			}
			page := &gossip.Message{Type: gossip.MessageCatalogPage, CatalogPage: &corestate.CatalogPage{
				CatalogRoot: remote.CatalogRoot, NextCursor: "18",
			}}
			for range 3 {
				deliver(page)
			}
			want := []string{"send:fetch_catalog_page", "send:pong", "send:fetch_catalog_page"}
			if pingFirst {
				want[0], want[1] = want[1], want[0]
			}
			if !slices.Equal(sender.trace, want) {
				t.Fatalf("send trace = %v, want %v", sender.trace, want)
			}

			// A legacy peer can still use the unsolicited Ping responder.
			driver.Gossip.RemoveSession(peer)
			sender.trace = nil
			deliver(ping)
			if want := []string{"send:pong", "send:fetch_catalog_page"}; !slices.Equal(sender.trace, want) {
				t.Fatalf("unsolicited send trace = %v, want %v", sender.trace, want)
			}
		})
	}
}
