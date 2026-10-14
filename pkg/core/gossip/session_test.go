package gossip

import (
	"bytes"
	"errors"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestSyncSessionIdleToPingSent(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	actions, err := s.OnEvent(&SyncTimerEvent{PeerID: "peer-a"}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionSummarySent {
		t.Fatalf("expected state summary_sent, got %s", s.State)
	}

	assertActionTypes(t, actions, []string{"SendPingAction", "StartTimerAction"})

	ping := actions[0].(SendPingAction)
	if ping.PeerID != "peer-a" {
		t.Fatalf("ping peer = %q, want peer-a", ping.PeerID)
	}

	round := actions[1].(StartTimerAction)
	if round.Kind != "round" {
		t.Fatalf("expected round timer, got %s", round.Kind)
	}
	if !round.Deadline.After(now) {
		t.Fatalf("round deadline %v should be after now %v", round.Deadline, now)
	}
}

func TestSyncSessionPongNoDifferences(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a"}, now)
	now = now.Add(100 * time.Millisecond)

	actions, err := s.OnEvent(&PongReceivedEvent{
		PeerID:       "peer-a",
		Pong:         &Pong{},
		MissingZones: nil,
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionCompleted {
		t.Fatalf("expected state completed, got %s", s.State)
	}
	assertActionTypes(t, actions, nil)
}

func TestSyncSessionPongWithMissingZones(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a"}, now)
	now = now.Add(50 * time.Millisecond)

	actions, err := s.OnEvent(&PongReceivedEvent{
		PeerID:       "peer-a",
		Pong:         &Pong{},
		MissingZones: []zone.ZonePath{"node-a.catofes."},
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionObjectPulling {
		t.Fatalf("expected state object_pulling, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"StartObjectPullAction"})
	// Initial RTT is 1s; a 50ms sample should pull the estimate down toward the sample.
	if s.EstimatedRTT() >= InitialRTT {
		t.Fatalf("expected RTT estimate to decrease from initial %v, got %v", InitialRTT, s.EstimatedRTT())
	}
	if s.EstimatedRTT() <= 50*time.Millisecond {
		t.Fatalf("expected RTT estimate to remain above sample 50ms after one EWMA step, got %v", s.EstimatedRTT())
	}
}

func TestSyncSessionCatalogSummaryFetchesPages(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)
	localRoot := corestate.CatalogRoot([]corestate.ZoneDigest{{Zone: "catofes.", RootHash: []byte("local")}})
	remoteRoot := corestate.CatalogRoot([]corestate.ZoneDigest{{Zone: "node-a.catofes.", RootHash: []byte("remote")}})

	_, _ = s.OnEvent(&SyncTimerEvent{
		PeerID:       "peer-a",
		LocalSummary: &corestate.CatalogSummary{CatalogRoot: localRoot, ZoneCount: 1},
	}, now)
	actions, err := s.OnEvent(&PongReceivedEvent{
		PeerID: "peer-a",
		Pong:   &Pong{Summary: &corestate.CatalogSummary{CatalogRoot: remoteRoot, ZoneCount: 1}},
	}, now.Add(10*time.Millisecond))
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionCatalogDiffing {
		t.Fatalf("expected state catalog_diffing, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"SendFetchCatalogPageAction", "StartTimerAction"})
}

func TestSyncSessionResponderPacketsDoNotEnterActivePullFSM(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)
	localRoot := corestate.CatalogRoot([]corestate.ZoneDigest{{Zone: "catofes.", RootHash: []byte("local")}})
	remoteRoot := corestate.CatalogRoot([]corestate.ZoneDigest{{Zone: "node-a.catofes.", RootHash: []byte("remote")}})

	_, _ = s.OnEvent(&SyncTimerEvent{
		PeerID:       "peer-a",
		LocalSummary: &corestate.CatalogSummary{CatalogRoot: localRoot, ZoneCount: 1},
	}, now)
	if s.State != SyncSessionSummarySent {
		t.Fatalf("expected state summary_sent, got %s", s.State)
	}

	actions, err := s.OnEvent(&PacketEvent{}, now.Add(5*time.Millisecond))
	if err == nil {
		t.Fatal("PacketEvent unexpectedly entered SyncSession")
	}
	if s.State != SyncSessionSummarySent {
		t.Fatalf("responder packet changed active pull state to %s", s.State)
	}
	if len(actions) != 0 {
		t.Fatalf("responder packet returned actions: %+v", actions)
	}

	actions, err = s.OnEvent(&PongReceivedEvent{
		PeerID: "peer-a",
		Pong:   &Pong{Summary: &corestate.CatalogSummary{CatalogRoot: remoteRoot, ZoneCount: 1}},
	}, now.Add(10*time.Millisecond))
	if err != nil {
		t.Fatalf("OnEvent(pong): %v", err)
	}
	if s.State != SyncSessionCatalogDiffing {
		t.Fatalf("expected pong to continue active pull into catalog_diffing, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"SendFetchCatalogPageAction", "StartTimerAction"})
}

func TestSyncSessionCatalogPageStartsObjectPull(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)
	local := []corestate.ZoneDigest{{Zone: "catofes.", RootHash: []byte("local")}}
	remote := []corestate.ZoneDigest{{Zone: "catofes.", RootHash: []byte("remote")}}
	root := corestate.CatalogRoot(remote)

	_, _ = s.OnEvent(&SyncTimerEvent{
		PeerID:       "peer-a",
		LocalSummary: &corestate.CatalogSummary{CatalogRoot: corestate.CatalogRoot(local), ZoneCount: 1},
	}, now)
	_, _ = s.OnEvent(&PongReceivedEvent{
		PeerID: "peer-a",
		Pong:   &Pong{Summary: &corestate.CatalogSummary{CatalogRoot: root, ZoneCount: 1}},
	}, now.Add(10*time.Millisecond))

	actions, err := s.OnEvent(&CatalogPageReceivedEvent{
		PeerID:       "peer-a",
		Page:         &corestate.CatalogPage{CatalogRoot: root, Entries: remote},
		LocalEntries: local,
	}, now.Add(20*time.Millisecond))
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionObjectPulling {
		t.Fatalf("expected state object_pulling, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"StartObjectPullAction"})
	if !s.pendingZones["catofes."] || !s.objectPullInflight["catofes."] {
		t.Fatalf("catalog diff did not mark zone pending/inflight")
	}
	applyActions, err := s.OnEvent(&ObjectPullResultEvent{
		PeerID:   "peer-a",
		Zone:     "catofes.",
		Snapshot: &corestate.ZoneSnapshot{Zone: "catofes."},
	}, now.Add(30*time.Millisecond))
	if err != nil {
		t.Fatalf("ObjectPullResultEvent: %v", err)
	}
	assertActionTypes(t, applyActions, []string{"ApplySnapshotAction"})
	apply := applyActions[0].(ApplySnapshotAction)
	if !apply.ReportResult || !bytes.Equal(apply.ExpectedRoot, remote[0].RootHash) || apply.Via != "object_pull" {
		t.Fatalf("apply action completion/root binding = %+v, want %x", apply, remote[0].RootHash)
	}
}

func TestSyncSessionCatalogPageRefreshesOnceOnRootMismatch(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)
	local := []corestate.ZoneDigest{{Zone: "catofes.", RootHash: []byte("local")}}
	remote := []corestate.ZoneDigest{{Zone: "catofes.", RootHash: []byte("remote")}}
	root := corestate.CatalogRoot(remote)

	_, _ = s.OnEvent(&SyncTimerEvent{
		PeerID:       "peer-a",
		LocalSummary: &corestate.CatalogSummary{CatalogRoot: corestate.CatalogRoot(local), ZoneCount: 1},
	}, now)
	_, _ = s.OnEvent(&PongReceivedEvent{
		PeerID: "peer-a",
		Pong:   &Pong{Summary: &corestate.CatalogSummary{CatalogRoot: root, ZoneCount: 1}},
	}, now.Add(10*time.Millisecond))

	actions, err := s.OnEvent(&CatalogPageReceivedEvent{
		PeerID:       "peer-a",
		Page:         &corestate.CatalogPage{CatalogRoot: []byte("wrong-root"), Entries: remote},
		LocalEntries: local,
	}, now.Add(20*time.Millisecond))
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionCatalogDiffing {
		t.Fatalf("expected catalog refresh, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"SendFetchCatalogPageAction", "StartTimerAction"})
	_, err = s.OnEvent(&CatalogPageReceivedEvent{PeerID: "peer-a", Page: &corestate.CatalogPage{CatalogRoot: root, Entries: remote, NextCursor: "1"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	actions, err = s.OnEvent(&CatalogPageReceivedEvent{PeerID: "peer-a", Page: &corestate.CatalogPage{CatalogRoot: []byte("wrong-again")}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if s.State != SyncSessionFailed {
		t.Fatalf("expected state failed, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"RecordBackoffAction"})
}

func TestSyncSessionCatalogPageBeforeTimerDoesNotPanic(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)
	local := []corestate.ZoneDigest{{Zone: "catofes.", RootHash: []byte("local")}}
	remote := []corestate.ZoneDigest{{Zone: "catofes.", RootHash: []byte("remote")}}
	root := corestate.CatalogRoot(remote)

	// A catalog page may arrive for a freshly created session before the
	// SyncTimerEvent has been processed (e.g. the timer event was dropped
	// because the event channel was full). The session must not panic.
	actions, err := s.OnEvent(&CatalogPageReceivedEvent{
		PeerID:       "peer-a",
		Page:         &corestate.CatalogPage{CatalogRoot: root, Entries: remote},
		LocalEntries: local,
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionObjectPulling {
		t.Fatalf("expected state object_pulling, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"StartObjectPullAction"})
}

func TestSyncSessionPongMissingZonesStartsObjectPull(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a"}, now)
	actions, err := s.OnEvent(&PongReceivedEvent{
		PeerID:       "peer-a",
		Pong:         &Pong{},
		MissingZones: []zone.ZonePath{"node-a.catofes.", "node-b.catofes."},
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionObjectPulling {
		t.Fatalf("expected state object_pulling, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"StartObjectPullAction", "StartObjectPullAction"})
}

func TestSyncSessionConcurrentObjectPullsComplete(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a"}, now)
	_, _ = s.OnEvent(&PongReceivedEvent{
		PeerID:       "peer-a",
		Pong:         &Pong{},
		MissingZones: []zone.ZonePath{"catofes.", "node-a.catofes."},
	}, now)

	if s.State != SyncSessionObjectPulling {
		t.Fatalf("expected state object_pulling, got %s", s.State)
	}

	// First result returns while the second pull is still in flight. The
	// session must stay in object_pulling so the second result is not dropped.
	actions1, err := s.OnEvent(&ObjectPullResultEvent{
		PeerID:   "peer-a",
		Zone:     "catofes.",
		Snapshot: &corestate.ZoneSnapshot{Zone: "catofes."},
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionObjectPulling {
		t.Fatalf("expected state object_pulling after first concurrent result, got %s", s.State)
	}
	assertActionTypes(t, actions1, []string{"ApplySnapshotAction"})

	// Second result returns, but the session must still wait for both runtime
	// apply acknowledgements before it can complete.
	actions2, err := s.OnEvent(&ObjectPullResultEvent{
		PeerID:   "peer-a",
		Zone:     "node-a.catofes.",
		Snapshot: &corestate.ZoneSnapshot{Zone: "node-a.catofes."},
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionObjectPulling {
		t.Fatalf("expected state object_pulling while applies are pending, got %s", s.State)
	}
	assertActionTypes(t, actions2, []string{"ApplySnapshotAction"})

	ack1, err := s.OnEvent(&SnapshotAppliedEvent{PeerID: "peer-a", Zone: "catofes."}, now)
	if err != nil {
		t.Fatalf("first SnapshotAppliedEvent: %v", err)
	}
	if s.State != SyncSessionObjectPulling || len(ack1) != 0 {
		t.Fatalf("first apply acknowledgement state/actions = %s/%v", s.State, ack1)
	}
	ack2, err := s.OnEvent(&SnapshotAppliedEvent{PeerID: "peer-a", Zone: "node-a.catofes."}, now)
	if err != nil {
		t.Fatalf("second SnapshotAppliedEvent: %v", err)
	}
	if s.State != SyncSessionCompleted {
		t.Fatalf("expected state completed after apply acknowledgements, got %s", s.State)
	}
	assertActionTypes(t, ack2, nil)
}

func TestSyncSessionConcurrentObjectPullsOneError(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a"}, now)
	_, _ = s.OnEvent(&PongReceivedEvent{
		PeerID:       "peer-a",
		Pong:         &Pong{},
		MissingZones: []zone.ZonePath{"catofes.", "node-a.catofes."},
	}, now)

	// First pull fails. We request chunk fallback but stay in object_pulling
	// because another pull is still in flight.
	actions1, err := s.OnEvent(&ObjectPullResultEvent{
		PeerID: "peer-a",
		Zone:   "catofes.",
		Err:    errors.New("tcp unreachable"),
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionObjectPulling {
		t.Fatalf("expected state object_pulling after first error with in-flight pull, got %s", s.State)
	}
	assertActionTypes(t, actions1, []string{"SendChunkFallbackAction"})

	// Second pull succeeds. Because a zone needs chunk fallback, we transition
	// to chunk_fallback instead of completed.
	actions2, err := s.OnEvent(&ObjectPullResultEvent{
		PeerID:   "peer-a",
		Zone:     "node-a.catofes.",
		Snapshot: &corestate.ZoneSnapshot{Zone: "node-a.catofes."},
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionChunkFallback {
		t.Fatalf("expected state chunk_fallback, got %s", s.State)
	}
	assertActionTypes(t, actions2, []string{"ApplySnapshotAction"})
}

func TestSyncSessionObjectPullSuccess(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a"}, now)
	_, _ = s.OnEvent(&PongReceivedEvent{
		PeerID:       "peer-a",
		Pong:         &Pong{},
		MissingZones: []zone.ZonePath{"node-a.catofes."},
	}, now)

	actions, err := s.OnEvent(&ObjectPullResultEvent{
		PeerID:   "peer-a",
		Zone:     "node-a.catofes.",
		Snapshot: &corestate.ZoneSnapshot{Zone: "node-a.catofes."},
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionObjectPulling {
		t.Fatalf("expected state object_pulling while apply is pending, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"ApplySnapshotAction"})
	if apply := actions[0].(ApplySnapshotAction); apply.Via != "object_pull" {
		t.Fatalf("object pull apply via = %q, want object_pull", apply.Via)
	}
	ack, err := s.OnEvent(&SnapshotAppliedEvent{PeerID: "peer-a", Zone: "node-a.catofes."}, now)
	if err != nil {
		t.Fatalf("SnapshotAppliedEvent: %v", err)
	}
	if s.State != SyncSessionCompleted {
		t.Fatalf("expected state completed after apply acknowledgement, got %s", s.State)
	}
	assertActionTypes(t, ack, nil)
}

func TestSyncSessionObjectPullErrorFallsBackToChunk(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a"}, now)
	_, _ = s.OnEvent(&PongReceivedEvent{
		PeerID:       "peer-a",
		Pong:         &Pong{},
		MissingZones: []zone.ZonePath{"node-a.catofes."},
	}, now)

	actions, err := s.OnEvent(&ObjectPullResultEvent{
		PeerID: "peer-a",
		Zone:   "node-a.catofes.",
		Err:    errors.New("tcp unreachable"),
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionChunkFallback {
		t.Fatalf("expected state chunk_fallback, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"SendChunkFallbackAction"})
	fz := actions[0].(SendChunkFallbackAction)
	if fz.Zone != "node-a.catofes." {
		t.Fatalf("unexpected fetch zone action: %+v", fz)
	}
}

func TestSyncSessionChunkComplete(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a"}, now)
	_, _ = s.OnEvent(&PongReceivedEvent{
		PeerID:       "peer-a",
		Pong:         &Pong{},
		MissingZones: []zone.ZonePath{"node-a.catofes."},
	}, now)
	_, _ = s.OnEvent(&ObjectPullResultEvent{PeerID: "peer-a", Zone: "node-a.catofes.", Err: errors.New("tcp unreachable")}, now)

	actions, err := s.OnEvent(&ObjectChunkEvent{
		PeerID:   "peer-a",
		Zone:     "node-a.catofes.",
		Snapshot: &corestate.ZoneSnapshot{Zone: "node-a.catofes."},
	}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionChunkFallback {
		t.Fatalf("expected state chunk_fallback while apply is pending, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"ApplySnapshotAction"})
	if apply := actions[0].(ApplySnapshotAction); apply.Via != "udp_chunks" {
		t.Fatalf("chunk apply via = %q, want udp_chunks", apply.Via)
	}
	ack, err := s.OnEvent(&SnapshotAppliedEvent{PeerID: "peer-a", Zone: "node-a.catofes."}, now)
	if err != nil {
		t.Fatalf("SnapshotAppliedEvent: %v", err)
	}
	if s.State != SyncSessionCompleted {
		t.Fatalf("expected state completed after chunk apply acknowledgement, got %s", s.State)
	}
	assertActionTypes(t, ack, nil)
}

func TestSyncSessionSnapshotAppliedCompletesAfterValidatedMerge(t *testing.T) {
	s := NewSyncSession("peer-a")
	s.State = SyncSessionObjectPulling
	s.pendingZones["catofes."] = true
	s.snapshotApplyPending["catofes."] = true
	s.expectedDigests["catofes."] = corestate.ZoneDigest{Zone: "catofes.", RootHash: []byte("expected")}

	actions, err := s.OnEvent(&SnapshotAppliedEvent{
		PeerID: "peer-a",
		Zone:   "catofes.",
	}, time.Unix(1000, 0))
	if err != nil {
		t.Fatalf("SnapshotAppliedEvent: %v", err)
	}
	if s.State != SyncSessionCompleted {
		t.Fatalf("state = %s, want completed", s.State)
	}
	assertActionTypes(t, actions, nil)
}

func TestSyncSessionRoundTimeout(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a"}, now)
	actions, err := s.OnEvent(&RoundTimeoutEvent{PeerID: "peer-a"}, now)
	if err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}
	if s.State != SyncSessionFailed {
		t.Fatalf("expected state failed, got %s", s.State)
	}
	assertActionTypes(t, actions, []string{"RecordBackoffAction", "CancelTimerAction"})
}

func TestSyncSessionRTTAwareTimeouts(t *testing.T) {
	s := NewSyncSession("peer-a")
	now := time.Unix(1000, 0)

	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a"}, now)
	// Simulate a 600ms RTT.
	_, _ = s.OnEvent(&PongReceivedEvent{PeerID: "peer-a", Pong: &Pong{}}, now.Add(600*time.Millisecond))

	catalogPage := s.catalogPageTimeout()
	expectedMin := time.Duration(kCatalogPageTimeoutMultiplier) * 600 * time.Millisecond
	if catalogPage < expectedMin {
		t.Fatalf("catalog page timeout %v should be >= %v", catalogPage, expectedMin)
	}
	if catalogPage < MinCatalogPageTimeout {
		t.Fatalf("catalog page timeout %v should respect min %v", catalogPage, MinCatalogPageTimeout)
	}

	round := s.roundTimeout()
	expectedRoundMin := time.Duration(kRoundMultiplier)*600*time.Millisecond + ObjectPullBudget
	if round < expectedRoundMin {
		t.Fatalf("round timeout %v should be >= %v", round, expectedRoundMin)
	}
	if round < MinRoundTimeout {
		t.Fatalf("round timeout %v should respect min %v", round, MinRoundTimeout)
	}
}

func TestSyncSessionDone(t *testing.T) {
	s := NewSyncSession("peer-a")
	if s.Done() {
		t.Fatal("new session should not be done")
	}
	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer-a"}, time.Unix(1000, 0))
	_, _ = s.OnEvent(&RoundTimeoutEvent{PeerID: "peer-a"}, time.Unix(1000, 0))
	if !s.Done() {
		t.Fatal("failed session should be done")
	}
}

func assertActionTypes(t *testing.T, actions []SyncAction, want []string) {
	t.Helper()
	if len(actions) != len(want) {
		t.Fatalf("expected %d actions (%v), got %d (%v)", len(want), want, len(actions), actionTypes(actions))
	}
	for i, a := range actions {
		got := actionType(a)
		if got != want[i] {
			t.Fatalf("action %d: expected %s, got %s", i, want[i], got)
		}
	}
}

func actionType(a SyncAction) string {
	switch a.(type) {
	case SendPingAction:
		return "SendPingAction"
	case SendChunkFallbackAction:
		return "SendChunkFallbackAction"
	case SendFetchCatalogPageAction:
		return "SendFetchCatalogPageAction"
	case StartObjectPullAction:
		return "StartObjectPullAction"
	case ApplySnapshotAction:
		return "ApplySnapshotAction"
	case RecordBackoffAction:
		return "RecordBackoffAction"
	case StartTimerAction:
		return "StartTimerAction"
	case CancelTimerAction:
		return "CancelTimerAction"
	default:
		return "unknown"
	}
}

func actionTypes(actions []SyncAction) []string {
	out := make([]string, len(actions))
	for i, a := range actions {
		out[i] = actionType(a)
	}
	return out
}
