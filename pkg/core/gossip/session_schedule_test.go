package gossip

import (
	"errors"
	"reflect"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func scheduledPulls(actions []SyncAction) []zone.ZonePath {
	var paths []zone.ZonePath
	for _, action := range actions {
		if pull, ok := action.(StartObjectPullAction); ok {
			paths = append(paths, pull.Zone)
		}
	}
	return paths
}

func TestSyncSessionSchedulesCompleteCatalogAndWaitsForAncestorApply(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewSyncSession("peer")
	event := func(e SyncEvent) []SyncAction {
		t.Helper()
		actions, err := s.OnEvent(e, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(s.objectPullInflight)+len(s.snapshotApplyPending)+len(s.chunkFallbackZones) > maxSessionObjectPulls {
			t.Fatal("exceeded bounded pull/apply/fallback window")
		}
		return actions
	}
	wantPulls := func(actions []SyncAction, paths ...zone.ZonePath) {
		t.Helper()
		if got := scheduledPulls(actions); !reflect.DeepEqual(got, paths) {
			t.Fatalf("scheduled %v, want %v (state %s)", got, paths, s.State)
		}
	}
	event(&SyncTimerEvent{PeerID: "peer"})
	children := []corestate.ZoneDigest{{Zone: "node.a.", RootHash: []byte("child")}}
	first := event(&CatalogPageReceivedEvent{PeerID: "peer", Page: &corestate.CatalogPage{CatalogRoot: []byte("catalog"), Entries: children, NextCursor: "parents"}})
	wantPulls(first)
	// Reconciliation during collection cannot schedule a child whose parent
	// may still be on a later page, nor complete the unfinished catalog.
	wantPulls(s.ReconcilePendingWithDigests(children))
	if s.State != SyncSessionCatalogDiffing {
		t.Fatalf("unfinished catalog state %s", s.State)
	}
	parents := []corestate.ZoneDigest{{Zone: "d.", RootHash: []byte("d")}, {Zone: "b.", RootHash: []byte("b")}, {Zone: "a.", RootHash: []byte("a")}, {Zone: "c.", RootHash: []byte("c")}}
	last := event(&CatalogPageReceivedEvent{PeerID: "peer", Page: &corestate.CatalogPage{CatalogRoot: []byte("catalog"), Entries: parents}})
	wantPulls(last, "a.", "b.")
	// A's completed download still occupies its slot until the apply ACK.
	wantPulls(event(&ObjectPullResultEvent{PeerID: "peer", Zone: "a.", Snapshot: &corestate.ZoneSnapshot{Zone: "a."}}))
	// B's TCP failure retains its slot while UDP fallback is outstanding.
	wantPulls(event(&ObjectPullResultEvent{PeerID: "peer", Zone: "b.", Err: errors.New("TCP unavailable")}))
	wantPulls(event(&SnapshotAppliedEvent{PeerID: "peer", Zone: "a."}), "c.")
	wantPulls(event(&ObjectChunkEvent{PeerID: "peer", Zone: "b.", Snapshot: &corestate.ZoneSnapshot{Zone: "b."}}))
	wantPulls(event(&SnapshotAppliedEvent{PeerID: "peer", Zone: "b."}), "d.")
	for _, path := range []zone.ZonePath{"c.", "d."} {
		wantPulls(event(&ObjectPullResultEvent{PeerID: "peer", Zone: path, Snapshot: &corestate.ZoneSnapshot{Zone: path}}))
		wantPulls(event(&SnapshotAppliedEvent{PeerID: "peer", Zone: path}))
	}
	if !s.Done() || s.State != SyncSessionCompleted {
		t.Fatalf("did not complete known child and parent catalog: %s", s.State)
	}
}

func TestSyncSessionQueuedDescendantStartsOnlyAfterParentAck(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewSyncSession("peer")
	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer"}, now)
	actions, _ := s.OnEvent(&PongReceivedEvent{PeerID: "peer", Pong: &Pong{}, MissingZones: []zone.ZonePath{"node.catofes.", "catofes."}}, now)
	if got := scheduledPulls(actions); !reflect.DeepEqual(got, []zone.ZonePath{"catofes."}) {
		t.Fatalf("initial ancestor pulls %v", got)
	}
	actions, _ = s.OnEvent(&ObjectPullResultEvent{PeerID: "peer", Zone: "catofes.", Snapshot: &corestate.ZoneSnapshot{Zone: "catofes."}}, now)
	if len(scheduledPulls(actions)) != 0 || s.objectPullInflight["node.catofes."] {
		t.Fatal("child started before parent apply")
	}
	actions, _ = s.OnEvent(&SnapshotAppliedEvent{PeerID: "peer", Zone: "catofes."}, now)
	if got := scheduledPulls(actions); !reflect.DeepEqual(got, []zone.ZonePath{"node.catofes."}) {
		t.Fatalf("child not scheduled after parent ACK: %v", got)
	}
	// A bounded session still terminates when a peer never returns its child.
	_, _ = s.OnEvent(&RoundTimeoutEvent{PeerID: "peer"}, now.Add(s.roundTimeout()))
	if s.State != SyncSessionFailed || s.LastError() == nil {
		t.Fatal("queued work escaped round deadline")
	}
}

func TestSyncSessionReconciledQueuedAncestorUnblocksDescendant(t *testing.T) {
	s := NewSyncSession("peer")
	s.State = SyncSessionObjectPulling
	for _, path := range []zone.ZonePath{"catofes.", "node.catofes."} {
		s.pendingZones[path] = true
		s.expectedDigests[path] = corestate.ZoneDigest{Zone: path, RootHash: []byte(path)}
	}
	actions := s.ReconcilePendingWithDigests([]corestate.ZoneDigest{{Zone: "catofes.", RootHash: []byte("catofes.")}})
	if got := scheduledPulls(actions); !reflect.DeepEqual(got, []zone.ZonePath{"node.catofes."}) || s.State != SyncSessionObjectPulling {
		t.Fatalf("reconciled parent did not unblock child: %v / %s", got, s.State)
	}
}

func TestSyncSessionRejectedAncestorDoesNotScheduleDescendant(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewSyncSession("peer")
	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer"}, now)
	_, _ = s.OnEvent(&PongReceivedEvent{PeerID: "peer", Pong: &Pong{}, MissingZones: []zone.ZonePath{"node.catofes.", "catofes."}}, now)
	_, _ = s.OnEvent(&ObjectPullResultEvent{PeerID: "peer", Zone: "catofes.", Snapshot: &corestate.ZoneSnapshot{Zone: "catofes."}}, now)
	rejected := errors.New("invalid signature")
	actions, err := s.OnEvent(&SnapshotAppliedEvent{PeerID: "peer", Zone: "catofes.", Err: rejected}, now)
	if err != nil || s.State != SyncSessionFailed || !errors.Is(s.LastError(), rejected) || len(scheduledPulls(actions)) != 0 {
		t.Fatalf("invalid ancestor did not terminate safely: state=%s actions=%v error=%v", s.State, actions, err)
	}
	if len(scheduledPulls(s.ReconcilePendingWithDigests(nil))) != 0 {
		t.Fatal("terminal session scheduled queued child")
	}
}
